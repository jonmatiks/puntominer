//! The GPU header search: a persistent `wgpu` engine over `miner.wgsl`.
//!
//! The division of labour is the one `docs/architecture.md` describes. The
//! host owns everything that
//! changes the merkle root — the coinbase, the extranonce, and therefore the
//! midstate — and the GPU owns the nonce space under one midstate. A dispatch
//! is `lanes * nonces_per_lane` nonces and returns the ones that met the
//! target.
//!
//! One rule holds throughout: **the GPU proposes and the host disposes.** A
//! returned nonce is a claim, not a result; [`GpuMiner::verify`] recomputes it
//! with `rust-bitcoin` and the caller only ever submits what that confirms.

use std::{
    borrow::Cow,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use bitcoin::{
    Block, ScriptBuf, Target,
    block::{Header, Version},
    hashes::Hash,
};
use bytemuck::{Pod, Zeroable};
use wgpu::util::DeviceExt;

use crate::{block::NONCE_MAX, constants::MINER_GPU_THROTTLE_WINDOW_MILLISECONDS};

use super::{
    block::{Extranonce, VersionRoll, build_block, difficulty_of_hash},
    cpu::{Mined, Search},
    sha256::{self, Backend, HeaderHasher},
    template::Template,
    watch::{Ending, Signals},
};

/// The longest a resting card goes without looking at its signals.
const REST_SLICE: Duration = Duration::from_millis(50);

/// Invocations per workgroup. Matches `miner.wgsl`.
const WORKGROUP_SIZE: u32 = 64;

/// Words the probe entry point writes per lane.
const DIGEST_WORDS: usize = 8;

/// Alternating dispatch slots. Two is enough to keep one
/// dispatch executing while the host reads the previous one back; a third would
/// only add latency between finding a block and hearing about it.
const SLOTS: usize = 2;

/// Uniform block handed to the shader. The `vec4` grouping is the uniform
/// layout rule: an `array<u32, N>` in a uniform block is padded to sixteen
/// bytes per element, which would waste three quarters of it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
struct GpuParams {
    midstate: [u32; 8],
    tail: [u32; 16],
    threshold: [u32; 8],
    base_nonce: u32,
    nonces_per_lane: u32,
    lanes: u32,
    capacity: u32,
    /// `search_pair`'s second midstate, appended so every field above keeps
    /// its offset. Zero for every other entry point.
    pair_midstate: [u32; 8],
}

/// Header of the winner buffer, mirroring `Winners` in the shader.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
struct WinnerHeader {
    count: u32,
    overflow: u32,
    /// The best rank any lane reported, and the nonce behind it. See
    /// [`sha256::best_rank`].
    best: u32,
    best_nonce: u32,
}

impl WinnerHeader {
    /// The state a dispatch starts from.
    ///
    /// **Not `Default`**, which is why the derive is gone: every counter here
    /// starts at zero and the best rank starts at the worst one, because a
    /// dispatch that cleared it to zero would claim the best possible hash and
    /// never be improved on by a real one.
    fn fresh() -> Self {
        Self {
            count: 0,
            overflow: 0,
            best: u32::MAX,
            best_nonce: 0,
        }
    }
}

/// What one dispatch found.
///
/// `overflowed` is reported rather than raised, because the two callers want
/// opposite things from it. For a block search every winner is equally a block
/// and only one can be submitted, so a search that found more than it could
/// record has still succeeded. The probe, which compares whole winner *sets*,
/// treats the same flag as fatal.
#[derive(Clone, Debug)]
pub struct Winners {
    pub nonces: Vec<u32>,
    pub overflowed: bool,
    /// The best rank a lane reported, for comparing one device's ranking with
    /// another's — which is all the probe needs and more than a run does.
    pub best_rank: u32,
    /// The nonce behind that rank. `None` when what came back is not a nonce
    /// this dispatch walked, which is the state a dispatch that reported
    /// nothing leaves behind.
    pub best_nonce: Option<u32>,
}

/// How much of the nonce space one dispatch covers, and how many dispatches
/// are allowed to be in flight at once.
#[derive(Clone, Copy, Debug)]
pub struct GpuConfig {
    pub lanes: u32,
    pub nonces_per_lane: u32,
    /// Winners one dispatch may record. Overflow is an error, not a truncation.
    pub capacity: u32,
    /// Dispatches in flight: 1 submits and waits, 2 submits the next before
    /// reading the previous one back. Kept configurable because it is the only
    /// honest way to measure what the overlap is worth.
    pub pipeline: u32,
    /// Duty cycle, 1 to 100. See `MINER_GPU_PERCENT`.
    pub load_percent: u8,
}

impl GpuConfig {
    pub fn validate(self) -> Result<Self, String> {
        if self.lanes == 0 {
            return Err("MINER_GPU_LANES must be greater than zero".into());
        }
        if self.nonces_per_lane == 0 {
            return Err("MINER_GPU_NONCES must be greater than zero".into());
        }
        if self.capacity == 0 {
            return Err("the GPU winner capacity must be greater than zero".into());
        }
        if self.pipeline == 0 || self.pipeline as usize > SLOTS {
            return Err(format!(
                "MINER_GPU_PIPELINE must be 1 or {SLOTS}, got {}",
                self.pipeline
            ));
        }
        if !(1..=100).contains(&self.load_percent) {
            return Err("MINER_GPU_PERCENT must be between 1 and 100".into());
        }
        // The nonce space is 32 bits and a dispatch covers `lanes * nonces`;
        // asking for more than fits means lanes would silently overlap.
        if u64::from(self.lanes) * u64::from(self.nonces_per_lane) > u64::from(NONCE_MAX) + 1 {
            return Err(format!(
                "{} lanes x {} nonces exceeds the 32-bit nonce space",
                self.lanes, self.nonces_per_lane
            ));
        }
        Ok(self)
    }

    /// Nonces one dispatch covers.
    pub fn nonces_per_dispatch(self) -> u64 {
        u64::from(self.lanes) * u64::from(self.nonces_per_lane)
    }

    /// Whether a dispatch may be submitted before the previous one is read.
    pub fn pipelined(self) -> bool {
        self.pipeline > 1
    }
}

/// The adapter a run selected, for reporting.
#[derive(Clone, Debug)]
pub struct GpuAdapter {
    pub name: String,
    pub backend: String,
}

/// Everything one dispatch writes, and the bind group pointing at it.
///
/// There are two of these so a dispatch can be executing into one while the
/// host reads the other back. Sharing a single set would mean the readback had
/// to finish before the next dispatch could even be submitted, which is the gap
/// [`GpuMiner::advance`] exists to close.
struct Slot {
    params: wgpu::Buffer,
    winners: wgpu::Buffer,
    readback: wgpu::Buffer,
    bind_group: wgpu::BindGroup,
}

/// A dispatch that has been submitted but not yet read.
struct Pending {
    slot: usize,
    base_nonce: u32,
    nonces: u64,
    /// The headers it was submitted under. Held so that handing the engine
    /// different ones while this is in flight is a named error rather than a
    /// dispatch whose winners get verified against the wrong block.
    headers: Headers,
}

/// What one dispatch hashes: one header, or two that differ only in their
/// version — a rolled pair, which `search_pair` hashes together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Headers {
    One(Header),
    Pair([Header; 2]),
}

impl Headers {
    /// A rolled pair, refused unless the two headers differ in their version
    /// and nothing else: `search_pair` shares the final block between them, so
    /// anything else would hash one header and report another.
    pub fn pair(first: Header, second: Header) -> Result<Self, String> {
        let same_tail = Header {
            version: first.version,
            ..second
        } == first;
        if !same_tail || first.version == second.version {
            return Err(
                "a GPU pair must be one header under two versions, and nothing else different"
                    .into(),
            );
        }
        Ok(Self::Pair([first, second]))
    }

    /// The headers, in the order the shader takes their midstates.
    pub fn as_slice(&self) -> &[Header] {
        match self {
            Self::One(header) => std::slice::from_ref(header),
            Self::Pair(headers) => headers,
        }
    }

    /// Hashes per nonce.
    fn count(&self) -> u64 {
        self.as_slice().len() as u64
    }
}

/// A duty cycle for the card.
///
/// The CPU's throttle cannot be copied here, because the host cannot pause a
/// dispatch: the card is paused *between* dispatches, and only once nothing is
/// queued behind the one it is walking. So this rests after whole dispatches,
/// and sleeps in proportion to the work it actually did rather than out the
/// rest of a fixed window — a window of 1,000 ms is about six dispatches at the
/// default size, and rounding each rest to one of them would miss the
/// requested share by up to a sixth.
///
/// It is `None` at 100%, for the reason `cpu.rs` gives: a full-speed search is
/// what the rest of this project measures, and it must not change shape to
/// support a feature it is not using.
#[derive(Clone, Copy, Debug)]
struct Duty {
    percent: u8,
    /// How much busy time earns a rest.
    work: Duration,
}

impl Duty {
    fn new(percent: u8) -> Option<Self> {
        if percent >= 100 {
            return None;
        }
        let window = Duration::from_millis(MINER_GPU_THROTTLE_WINDOW_MILLISECONDS);
        Some(Self {
            percent,
            work: window.mul_f64(f64::from(percent) / 100.0),
        })
    }

    /// How long a card that has been busy for `busy` must rest, so that it
    /// worked for `percent` of the two together.
    fn rest_for(self, busy: Duration) -> Duration {
        busy.mul_f64(f64::from(100 - self.percent) / f64::from(self.percent))
    }
}

/// A dispatch that has been read back.
///
/// It carries the span it covered because the caller cannot infer it: with a
/// dispatch in flight, the nonce the host is about to submit is no longer the
/// nonce the winners belong to.
#[derive(Clone, Debug)]
pub struct Completed {
    pub base_nonce: u32,
    pub nonces: u64,
    /// Headers hashed: `nonces` times the versions per nonce, which is two
    /// for a pair dispatch. What a rate is computed from.
    pub hashes: u64,
    pub winners: Winners,
    /// What the best hash of this dispatch was worth, hashed again through
    /// `rust-bitcoin`. Zero when the dispatch reported no nonce of its own.
    pub best: f64,
}

/// A persistent GPU search engine.
///
/// Adapter selection, shader compilation and buffer allocation all happen in
/// [`GpuMiner::new`] and are unreachable from the search loop. Only the
/// uniform block changes per dispatch.
pub struct GpuMiner {
    adapter: GpuAdapter,
    device: wgpu::Device,
    queue: wgpu::Queue,
    search_pipeline: wgpu::ComputePipeline,
    pair_pipeline: wgpu::ComputePipeline,
    probe_pipeline: wgpu::ComputePipeline,
    slots: [Slot; SLOTS],
    /// The dispatch that has been submitted and not yet collected.
    pending: Option<Pending>,
    digest_buffer: wgpu::Buffer,
    digest_readback: wgpu::Buffer,
    config: GpuConfig,
    winner_size: wgpu::BufferAddress,
    digest_size: wgpu::BufferAddress,
    duty: Option<Duty>,
    /// Time the card has spent walking nonces since it last rested.
    busy: Duration,
    /// When the card last went from idle to busy, while it still is. Kept
    /// apart from `busy` so that the time between searches — a template being
    /// fetched, a pool not having sent a job — is idle time rather than work
    /// the next rest has to pay for.
    busy_since: Option<Instant>,
}

impl GpuMiner {
    pub fn new(config: GpuConfig) -> Result<Self, String> {
        pollster::block_on(Self::new_async(config))
    }

    async fn new_async(config: GpuConfig) -> Result<Self, String> {
        let config = config.validate()?;

        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor::new_without_display_handle());
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                ..Default::default()
            })
            .await
            .map_err(|error| format!("could not find a GPU adapter: {error}"))?;
        let adapter_info = adapter.get_info();

        // This needs no SHADER_INT64: SHA-256 is 32-bit
        // arithmetic throughout, so the shader runs on any compute-capable
        // adapter.
        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor {
                label: Some("bitcoin-in-depth GPU miner"),
                ..Default::default()
            })
            .await
            .map_err(|error| format!("could not create GPU device: {error}"))?;

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("GPU header search"),
            source: wgpu::ShaderSource::Wgsl(Cow::Owned(shader_source())),
        });

        let winner_size = (size_of::<WinnerHeader>() + config.capacity as usize * size_of::<u32>())
            as wgpu::BufferAddress;
        let digest_size =
            (config.lanes as usize * DIGEST_WORDS * size_of::<u32>()) as wgpu::BufferAddress;

        let digest_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("GPU miner digests"),
            size: digest_size,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        let digest_readback = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("GPU miner digest readback"),
            size: digest_size,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });

        // The layout is explicit rather than inferred. An inferred layout
        // contains only the bindings its entry point actually uses — `search`
        // never touches the digest buffer and `probe` never touches the winner
        // buffer — so neither would accept a bind group holding all three.
        let layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("GPU miner layout"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("GPU miner pipeline layout"),
            bind_group_layouts: &[Some(&layout)],
            immediate_size: 0,
        });

        let search_pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("GPU header search"),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: Some("search"),
            compilation_options: Default::default(),
            cache: None,
        });
        // Its own pipeline, and therefore its own register allocation: the
        // pair kernel holds two working states, and `search` must not pay for
        // them.
        let pair_pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("GPU header pair search"),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: Some("search_pair"),
            compilation_options: Default::default(),
            cache: None,
        });
        let probe_pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("GPU header probe"),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: Some("probe"),
            compilation_options: Default::default(),
            cache: None,
        });

        // One set of buffers per slot, differing only in which winner buffer
        // the bind group points at. The digest buffer is shared: the probe that
        // uses it is unpipelined by nature, since it reads every lane.
        let slots = std::array::from_fn(|slot| {
            let params = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some(&format!("GPU miner params {slot}")),
                size: size_of::<GpuParams>() as wgpu::BufferAddress,
                usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let winners = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some(&format!("GPU miner winners {slot}")),
                contents: &vec![0u8; winner_size as usize],
                usage: wgpu::BufferUsages::STORAGE
                    | wgpu::BufferUsages::COPY_SRC
                    | wgpu::BufferUsages::COPY_DST,
            });
            let readback = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some(&format!("GPU miner winner readback {slot}")),
                size: winner_size,
                usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
                mapped_at_creation: false,
            });
            let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some(&format!("GPU miner bindings {slot}")),
                layout: &layout,
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: params.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: winners.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 2,
                        resource: digest_buffer.as_entire_binding(),
                    },
                ],
            });
            Slot {
                params,
                winners,
                readback,
                bind_group,
            }
        });

        Ok(Self {
            adapter: GpuAdapter {
                name: adapter_info.name,
                backend: format!("{:?}", adapter_info.backend),
            },
            device,
            queue,
            search_pipeline,
            pair_pipeline,
            probe_pipeline,
            slots,
            pending: None,
            digest_buffer,
            digest_readback,
            config,
            winner_size,
            digest_size,
            duty: Duty::new(config.load_percent),
            busy: Duration::ZERO,
            busy_since: None,
        })
    }

    pub fn adapter(&self) -> &GpuAdapter {
        &self.adapter
    }

    pub fn config(&self) -> GpuConfig {
        self.config
    }

    /// Submit a dispatch and return the previous one's winners.
    ///
    /// The ordering is what makes the pipeline work: the copy of the finished
    /// dispatch is queued *before* the new dispatch, so on an in-order queue it
    /// completes first and waiting for it does not wait for the work just
    /// submitted. The host verifies one dispatch's winners while the GPU is
    /// already walking the next span.
    ///
    /// The first call has nothing to return. [`Self::finish`] drains what is
    /// left, and **must be called before the header changes** — the winners
    /// still in flight belong to the header that was passed when they were
    /// submitted, and verifying them against a new merkle root would be
    /// meaningless. Passing a different header while one is pending is
    /// therefore an error rather than a quietly wrong answer.
    ///
    /// At `pipeline = 1` there is no overlap: the dispatch is submitted, waited
    /// for, and returned by the same call.
    pub fn advance(
        &mut self,
        header: &Header,
        target: Target,
        nonce_base: u32,
    ) -> Result<Option<Completed>, String> {
        self.advance_headers(&Headers::One(*header), target, nonce_base)
    }

    /// [`Self::advance`] over one header or a rolled pair. A pair dispatches
    /// `search_pair`, which hashes both versions at every nonce; the rules on
    /// what is in flight apply to the pair as a whole.
    pub fn advance_headers(
        &mut self,
        headers: &Headers,
        target: Target,
        nonce_base: u32,
    ) -> Result<Option<Completed>, String> {
        // A dispatch covers a fixed number of nonces and knows nothing about
        // the range its caller is walking: the only thing that can shorten it
        // is the end of the 32-bit nonce, past which the shader would wrap and
        // count the same nonces twice. A caller walking a sub-range therefore
        // overshoots its own end by up to one dispatch, and the hash count says
        // what was dispatched rather than what was asked for.
        let nonces = self
            .config
            .nonces_per_dispatch()
            .min(u64::from(NONCE_MAX - nonce_base) + 1);

        if !self.config.pipelined() {
            self.went_busy();
            self.submit_search(0, headers, target, nonce_base);
            let copy = self.submit_winner_copy(0);
            let winners = self.collect_winners(0, copy);
            self.went_idle();
            let winners = winners?;
            return Ok(Some(Completed {
                base_nonce: nonce_base,
                nonces,
                hashes: nonces * headers.count(),
                best: best_difficulty(headers, &winners, nonce_base, nonces),
                winners,
            }));
        }

        let pending = self.pending.take();
        if let Some(pending) = &pending
            && pending.headers != *headers
        {
            return Err(
                "the GPU was handed a new header while a dispatch from the previous one was \
                 still in flight: finish() first, or its winners would be checked against the \
                 wrong block"
                    .into(),
            );
        }

        if pending.is_none() {
            self.went_busy();
        }
        let copy = pending.as_ref().map(|p| self.submit_winner_copy(p.slot));
        let next = pending.as_ref().map_or(0, |p| (p.slot + 1) % SLOTS);
        self.submit_search(next, headers, target, nonce_base);
        self.pending = Some(Pending {
            slot: next,
            base_nonce: nonce_base,
            nonces,
            headers: *headers,
        });

        match (pending, copy) {
            (Some(pending), Some(copy)) => {
                let winners = self.collect_winners(pending.slot, copy)?;
                Ok(Some(Completed {
                    base_nonce: pending.base_nonce,
                    nonces: pending.nonces,
                    hashes: pending.nonces * pending.headers.count(),
                    // **The headers this dispatch was submitted under**, not
                    // the ones just handed over: the same reason its winners
                    // are verified against those.
                    best: best_difficulty(
                        &pending.headers,
                        &winners,
                        pending.base_nonce,
                        pending.nonces,
                    ),
                    winners,
                }))
            }
            _ => Ok(None),
        }
    }

    /// Read the dispatch [`Self::advance`] left in flight, leaving nothing
    /// pending. Returns `None` when there was nothing in flight.
    pub fn finish(&mut self) -> Result<Option<Completed>, String> {
        let Some(pending) = self.pending.take() else {
            return Ok(None);
        };
        let copy = self.submit_winner_copy(pending.slot);
        let winners = self.collect_winners(pending.slot, copy);
        self.went_idle();
        let winners = winners?;
        Ok(Some(Completed {
            base_nonce: pending.base_nonce,
            nonces: pending.nonces,
            hashes: pending.nonces * pending.headers.count(),
            best: best_difficulty(
                &pending.headers,
                &winners,
                pending.base_nonce,
                pending.nonces,
            ),
            winners,
        }))
    }

    /// Forget the dispatch in flight without waiting for it.
    ///
    /// The right thing to do once a block has been found: the work behind it
    /// covers the same header and could only find a second block that would
    /// never be submitted. Nothing has to be waited on, because the buffers it
    /// is still writing are reached only through its own slot and every later
    /// write to them is queued behind it.
    pub fn abandon(&mut self) {
        self.pending = None;
        self.went_idle();
    }

    /// Rest the card, if its duty cycle says it has earned it.
    ///
    /// A card with work queued is not resting, so this drains the dispatch in
    /// flight first and returns it — to be claimed like any other, since it
    /// covers the header the caller is still on. `None` means either nothing
    /// was in flight or no rest was due; at 100% it is always `None` and no
    /// clock is read.
    ///
    /// The sleep is sliced so that it ends as soon as `signals` does: a run
    /// asked to stop, a stale template, or the other half of a hybrid search
    /// having found the block must not wait out a rest that at 10% lasts nine
    /// times as long as the work before it.
    ///
    /// Only the block and share searches call this. The probe and the lottery
    /// run flat out: one is a correctness check and the other a measurement,
    /// and neither is the run a user throttles to keep the machine usable.
    pub fn rest(&mut self, signals: &Signals) -> Result<Option<Completed>, String> {
        let Some(duty) = self.duty else {
            return Ok(None);
        };
        let busy = self.busy
            + self
                .busy_since
                .map_or(Duration::ZERO, |since| since.elapsed());
        if busy < duty.work {
            return Ok(None);
        }

        let drained = self.finish()?;
        let until = Instant::now() + duty.rest_for(self.busy);
        self.busy = Duration::ZERO;
        while signals.interrupted().is_none() {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            thread::sleep(left.min(REST_SLICE));
        }
        Ok(drained)
    }

    fn went_busy(&mut self) {
        if self.duty.is_some() && self.busy_since.is_none() {
            self.busy_since = Some(Instant::now());
        }
    }

    fn went_idle(&mut self) {
        if let Some(since) = self.busy_since.take() {
            self.busy += since.elapsed();
        }
    }

    /// Search one span of nonces, start to finish, with no overlap.
    ///
    /// The probe's entry point, and the definition of what `advance` has to
    /// agree with.
    pub fn search(
        &mut self,
        header: &Header,
        target: Target,
        nonce_base: u32,
    ) -> Result<Winners, String> {
        self.search_headers(&Headers::One(*header), target, nonce_base)
    }

    /// [`Self::search`] over one header or a rolled pair.
    pub fn search_headers(
        &mut self,
        headers: &Headers,
        target: Target,
        nonce_base: u32,
    ) -> Result<Winners, String> {
        if self.pending.is_some() {
            return Err(
                "a dispatch is still in flight, so a one-shot search would return it \
                        instead of what it was asked for"
                    .into(),
            );
        }

        match self.advance_headers(headers, target, nonce_base)? {
            Some(completed) => Ok(completed.winners),
            None => Ok(self
                .finish()?
                .ok_or("the GPU lost the dispatch it had just submitted")?
                .winners),
        }
    }

    /// Hash `count` consecutive nonces and return the digests themselves.
    ///
    /// The search only ever reports a verdict, which a shader could produce
    /// while computing the wrong digest — a target comparison that is
    /// accidentally always false looks exactly like a run that found nothing.
    /// This returns the digests so the host can compare all 32 bytes.
    pub fn probe_digests(
        &self,
        header: &Header,
        base_nonce: u32,
        count: u32,
    ) -> Result<Vec<[u32; 8]>, String> {
        if count > self.config.lanes {
            return Err(format!(
                "the probe can hash at most {} nonces per call, asked for {count}",
                self.config.lanes
            ));
        }

        // The target is irrelevant here but must be something the shader can
        // read; an unreachable one keeps the winner buffer empty.
        self.write_params(0, &Headers::One(*header), Target::ZERO, base_nonce, count);
        self.dispatch(&self.probe_pipeline, 0, count);
        self.read_digests(count)
    }

    /// Recompute a claimed nonce with `rust-bitcoin`.
    ///
    /// Also what turns a ranked nonce into a difficulty — see
    /// [`best_difficulty`], which hashes rather than decodes the rank.
    ///
    /// This is the only thing that turns a GPU claim into a result. It is a
    /// free function of the header, so a caller cannot accidentally verify
    /// against whatever the GPU was told.
    pub fn verify(header: &Header, target: Target, nonce: u32) -> bool {
        let mut header = *header;
        header.nonce = nonce;
        target.is_met_by(header.block_hash())
    }

    /// Stage this slot's uniform block and empty its winner buffer, then
    /// dispatch. Both writes are queued ahead of the dispatch that reads them,
    /// so a slot whose previous dispatch is still executing is safe to prepare.
    fn submit_search(&self, slot: usize, headers: &Headers, target: Target, base_nonce: u32) {
        self.write_params(slot, headers, target, base_nonce, self.config.lanes);
        self.clear_winners(slot);
        let pipeline = match headers {
            Headers::One(_) => &self.search_pipeline,
            Headers::Pair(_) => &self.pair_pipeline,
        };
        self.dispatch(pipeline, slot, self.config.lanes);
    }

    fn write_params(
        &self,
        slot: usize,
        headers: &Headers,
        target: Target,
        base_nonce: u32,
        lanes: u32,
    ) {
        let prepared = sha256::GpuHeader::new(&headers.as_slice()[0]);
        let pair_midstate = match headers {
            Headers::One(_) => [0; 8],
            Headers::Pair([_, second]) => sha256::GpuHeader::new(second).midstate,
        };
        let params = GpuParams {
            midstate: prepared.midstate,
            tail: prepared.tail,
            threshold: sha256::target_words(target),
            base_nonce,
            nonces_per_lane: self.config.nonces_per_lane,
            lanes,
            capacity: self.config.capacity,
            pair_midstate,
        };
        self.queue
            .write_buffer(&self.slots[slot].params, 0, bytemuck::bytes_of(&params));
    }

    fn clear_winners(&self, slot: usize) {
        self.queue.write_buffer(
            &self.slots[slot].winners,
            0,
            bytemuck::bytes_of(&WinnerHeader::fresh()),
        );
    }

    fn dispatch(&self, pipeline: &wgpu::ComputePipeline, slot: usize, lanes: u32) {
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("GPU miner commands"),
            });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("GPU miner dispatch"),
                timestamp_writes: None,
            });
            pass.set_pipeline(pipeline);
            pass.set_bind_group(0, &self.slots[slot].bind_group, &[]);
            pass.dispatch_workgroups(lanes.div_ceil(WORKGROUP_SIZE), 1, 1);
        }
        self.queue.submit([encoder.finish()]);
    }

    /// Copy a device buffer into its readback buffer and wait for that copy.
    ///
    /// The queue is in order, so waiting on the copy also waits for the
    /// dispatch that produced what is being copied — the dispatch's own
    /// submission index does not need to be waited on separately.
    fn copy_back(
        &self,
        source: &wgpu::Buffer,
        destination: &wgpu::Buffer,
        size: wgpu::BufferAddress,
        label: &str,
    ) -> wgpu::SubmissionIndex {
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some(label) });
        encoder.copy_buffer_to_buffer(source, 0, destination, 0, size);
        self.queue.submit([encoder.finish()])
    }

    fn submit_winner_copy(&self, slot: usize) -> wgpu::SubmissionIndex {
        self.copy_back(
            &self.slots[slot].winners,
            &self.slots[slot].readback,
            self.winner_size,
            "GPU miner winner copy",
        )
    }

    fn collect_winners(
        &self,
        slot: usize,
        submission: wgpu::SubmissionIndex,
    ) -> Result<Winners, String> {
        let readback = &self.slots[slot].readback;
        let mapped = self.map_range(readback, submission)?;
        let header = *bytemuck::from_bytes::<WinnerHeader>(&mapped[..size_of::<WinnerHeader>()]);
        let stored = header.count.min(self.config.capacity) as usize;
        let end = size_of::<WinnerHeader>() + stored * size_of::<u32>();
        let nonces =
            bytemuck::cast_slice::<u8, u32>(&mapped[size_of::<WinnerHeader>()..end]).to_vec();
        drop(mapped);
        readback.unmap();

        Ok(Winners {
            nonces,
            overflowed: header.overflow != 0 || header.count > self.config.capacity,
            best_rank: header.best,
            best_nonce: Some(header.best_nonce),
        })
    }

    fn read_digests(&self, count: u32) -> Result<Vec<[u32; 8]>, String> {
        let submission = self.copy_back(
            &self.digest_buffer,
            &self.digest_readback,
            self.digest_size,
            "GPU miner digest copy",
        );

        let mapped = self.map_range(&self.digest_readback, submission)?;
        let words = bytemuck::cast_slice::<u8, u32>(&mapped);
        let digests = words
            .as_chunks::<DIGEST_WORDS>()
            .0
            .iter()
            .take(count as usize)
            .copied()
            .collect();
        drop(mapped);
        self.digest_readback.unmap();
        Ok(digests)
    }

    fn map_range(
        &self,
        buffer: &wgpu::Buffer,
        submission: wgpu::SubmissionIndex,
    ) -> Result<wgpu::BufferView, String> {
        let (mapped_tx, mapped_rx) = mpsc::sync_channel(1);
        buffer
            .slice(..)
            .map_async(wgpu::MapMode::Read, move |result| {
                let _ = mapped_tx.send(result);
            });
        self.wait_for(submission)?;
        mapped_rx
            .recv()
            .map_err(|error| format!("GPU map callback was lost: {error}"))?
            .map_err(|error| format!("could not map GPU buffer: {error}"))?;
        buffer
            .slice(..)
            .get_mapped_range()
            .map_err(|error| format!("could not read mapped GPU buffer: {error}"))
    }

    fn wait_for(&self, submission: wgpu::SubmissionIndex) -> Result<(), String> {
        self.device
            .poll(wgpu::PollType::Wait {
                submission_index: Some(submission),
                timeout: Some(Duration::from_secs(60)),
            })
            .map(|_| ())
            .map_err(|error| format!("GPU dispatch timed out: {error}"))
    }
}

/// Search a template on the GPU, mirroring [`super::cpu::search`].
///
/// The host walks extranonces and the GPU walks the nonce space under each,
/// which is the split `docs/architecture.md` describes. Every nonce the GPU
/// claims is recomputed here with `rust-bitcoin`; a claim it cannot reproduce
/// fails the run rather than being submitted or quietly skipped.
///
/// Dispatches overlap: the loop submits the next span before reading the
/// previous one back, so the card is not idle while the host checks winners.
/// The two places that overlap has to end are the two places the header
/// changes — an exhausted nonce space, and an interruption — and both drain the
/// engine before the merkle root moves under it.
///
/// `start` is where the walk begins. It has no bearing on the odds, only on
/// whether another instance sharing this payout address is walking the same
/// headers — see `MINER_EXTRANONCE_START`.
///
/// `mask` is the version bits it may roll: [`Template::rollable_bits`] when
/// `MINER_TEMPLATE_VERSION_ROLLING` is on, and zero otherwise. Zero is the
/// template's version alone, through the single-header kernel, with no branch
/// in the walk to say so. Anything else walks [`VersionRoll`]'s versions two
/// at a time through `search_pair` — AsicBoost — in the order nonce, then
/// version, then extranonce, and the first pair holds the template's own
/// version.
pub fn search(
    template: &Template,
    payout: &ScriptBuf,
    miner: &mut GpuMiner,
    signals: &Signals,
    start: Extranonce,
    mask: u32,
) -> Result<Search, String> {
    let started = Instant::now();
    let time = template.curtime.max(template.mintime);
    let span = miner.config().nonces_per_dispatch();

    let mut hashes = 0u64;
    let mut best = 0.0f64;
    let mut extranonce = start;

    loop {
        let block = build_block(template, payout, extranonce.0, time)?;
        let under = |version: u32| Header {
            version: Version::from_consensus(version as i32),
            ..block.header
        };

        // A span of two or more is a power of two, so it splits into pairs
        // exactly, and the two members of each differ only in the mask's
        // lowest bit. A span of one is the template's version, unchanged.
        let mut roll = VersionRoll::new(template.version as u32, mask);
        let paired = roll.span() >= 2;
        while let Some(rolled) = roll.next() {
            let headers = if paired {
                let partner = roll
                    .next()
                    .expect("a span of two or more versions is a power of two, so even");
                Headers::pair(under(rolled), under(partner))?
            } else {
                Headers::One(under(rolled))
            };

            // Kept as `u64` for the walk itself: `base` advances a whole
            // dispatch at a time and would overflow a nonce on the last step.
            let mut base = 0u64;
            while base <= u64::from(NONCE_MAX) {
                // Before the interruption check rather than after it, so a rest
                // that a stale template cut short is noticed at once.
                if let Some(done) = miner.rest(signals)? {
                    hashes += done.hashes;
                    best = best.max(done.best);
                    if let Some(winner) =
                        claim(&block, &headers, template.target, extranonce, &done)?
                    {
                        return Ok(found(winner, hashes, best, started));
                    }
                }

                // An interruption drains rather than discards: the work is
                // already done, and on a benchmark it is the last dispatch's
                // hashes that would otherwise go unreported.
                if let Some(ending) = signals.interrupted() {
                    if let Some(done) = miner.finish()? {
                        hashes += done.hashes;
                        best = best.max(done.best);
                        if let Some(winner) =
                            claim(&block, &headers, template.target, extranonce, &done)?
                        {
                            return Ok(found(winner, hashes, best, started));
                        }
                    }
                    return Ok(Search {
                        winner: None,
                        hashes,
                        seconds: started.elapsed().as_secs_f64(),
                        ending,
                        parts: Vec::new(),
                        best,
                    });
                }

                let completed = miner.advance_headers(&headers, template.target, base as u32)?;
                base += span;

                if let Some(done) = completed {
                    hashes += done.hashes;
                    best = best.max(done.best);
                    if let Some(winner) =
                        claim(&block, &headers, template.target, extranonce, &done)?
                    {
                        // Whatever is still executing covers this same pair, so
                        // it can only find a second block that would never be
                        // submitted. The dispatch abandoned with it takes its
                        // own best hash along, which is a statistic rather than
                        // a result and not worth waiting on.
                        miner.abandon();
                        return Ok(found(winner, hashes, best, started));
                    }
                }
            }

            // The nonce space is exhausted under these headers, so the version
            // or the merkle root has to change — which means nothing may still
            // be in flight under the old ones. A rolled version is as much a
            // different header as a new coinbase is.
            if let Some(done) = miner.finish()? {
                hashes += done.hashes;
                best = best.max(done.best);
                if let Some(winner) = claim(&block, &headers, template.target, extranonce, &done)? {
                    return Ok(found(winner, hashes, best, started));
                }
            }
        }
        extranonce = extranonce.advance(1);
    }
}

/// What the nonce a dispatch ranked best is actually worth.
///
/// **The shader ranks and `rust-bitcoin` measures.** The rank is one bit coarse
/// by construction and is only ever used to choose between two hashes; the
/// number that reaches a log comes from hashing the chosen nonce again the
/// trusted way, exactly as a winner does. So the reported difficulty is always
/// a real header's real hash, and the shader's ranking can only ever cost it a
/// little — never invent it.
///
/// A nonce outside the span this dispatch walked is not one of its hashes: it
/// is what a cleared buffer still holds when no lane wrote, and it is worth
/// nothing rather than worth whatever hashing it would produce.
fn best_difficulty(headers: &Headers, winners: &Winners, base_nonce: u32, nonces: u64) -> f64 {
    let Some(nonce) = winners.best_nonce else {
        return 0.0;
    };
    if u64::from(nonce.wrapping_sub(base_nonce)) >= nonces {
        return 0.0;
    }

    // A pair's best nonce does not say which version it was best under, so
    // both are hashed and the better one is what the dispatch was worth.
    headers
        .as_slice()
        .iter()
        .map(|header| {
            let mut header = *header;
            header.nonce = nonce;
            difficulty_of_hash(&header.block_hash())
        })
        .fold(0.0, f64::max)
}

/// Turn a completed dispatch into a block, if it found one.
///
/// The GPU proposes and `rust-bitcoin` disposes. The first winner is as good as
/// any other — they are all blocks and only one can be submitted, which is also
/// why an overflowed buffer does not matter here.
///
/// **The GPU never says which version won**, so under a pair the nonce is
/// verified under the first header and then the second, and the first that
/// verifies is the block — its version included. A nonce that verifies under
/// neither is an error, exactly as it is for one header.
fn claim(
    block: &Block,
    headers: &Headers,
    target: Target,
    extranonce: Extranonce,
    done: &Completed,
) -> Result<Option<Mined>, String> {
    let Some(nonce) = done.winners.nonces.first().copied() else {
        return Ok(None);
    };

    let Some(header) = headers
        .as_slice()
        .iter()
        .find(|header| GpuMiner::verify(header, target, nonce))
    else {
        return Err(format!(
            "the GPU claimed nonce {nonce} at extranonce {extranonce}, which rust-bitcoin rejects"
        ));
    };

    let mut block = block.clone();
    block.header = Header { nonce, ..*header };
    Ok(Some(Mined { block, extranonce }))
}

fn found(winner: Mined, hashes: u64, best: f64, started: Instant) -> Search {
    Search {
        winner: Some(winner),
        hashes,
        seconds: started.elapsed().as_secs_f64(),
        ending: Ending::Found,
        parts: Vec::new(),
        best,
    }
}

/// The correctness probe: every claim the GPU makes is checked against a trusted
/// implementation, and a failure names what disagreed.
pub fn probe(miner: &mut GpuMiner, log: &crate::logger::Logger) -> Result<(), String> {
    let headers = probe_headers();

    // 1. Whole digests, against `rust-bitcoin`.
    for (name, header) in &headers {
        let count = 256.min(miner.config().lanes);
        let digests = miner.probe_digests(header, 0, count)?;
        if digests.len() != count as usize {
            return Err(format!(
                "the probe asked for {count} digests on {name} and got {}",
                digests.len()
            ));
        }

        for (nonce, digest) in digests.iter().enumerate() {
            let mut expected = *header;
            expected.nonce = nonce as u32;
            let expected = expected.block_hash();
            let got = sha256::digest_bytes(digest);
            if got != expected.to_byte_array() {
                return Err(format!(
                    "{name}: the GPU digest at nonce {nonce} disagrees with rust-bitcoin"
                ));
            }
        }
        log.log(format!(
            "probe: {count} digests match rust-bitcoin on {name}"
        ));
    }

    // 2. The digest of a nonce far from zero, which the earlier sweep cannot
    //    reach and which catches a base-nonce that is ignored or truncated.
    let (name, header) = &headers[0];
    let base = 0xdead_0000u32;
    let digests = miner.probe_digests(header, base, 64)?;
    for (step, digest) in digests.iter().enumerate() {
        let mut expected = *header;
        expected.nonce = base + step as u32;
        if sha256::digest_bytes(digest) != expected.block_hash().to_byte_array() {
            return Err(format!(
                "{name}: the GPU digest at nonce {} disagrees with rust-bitcoin",
                base + step as u32
            ));
        }
    }
    log.log(format!("probe: 64 digests match at base nonce {base:#x}"));

    // 3. The winner set, against the CPU, over the same span. This is the
    //    check that catches a dropped winner, which the digest comparison
    //    cannot see and which on a real chain is a lost block.
    let target = Target::from_compact(bitcoin::CompactTarget::from_consensus(0x1f00_ffff));
    let span = miner.config().nonces_per_dispatch();
    let (_, header) = &headers[0];

    let claimed = miner.search(header, target, 0)?;
    if claimed.overflowed {
        return Err(
            "the probe's winner buffer overflowed, so the set comparison would prove nothing"
                .into(),
        );
    }
    let claimed_best = claimed.best_rank;
    let claimed_best_nonce = claimed.best_nonce;
    let claimed = claimed.nonces;
    let mut expected = Vec::new();
    let mut best_rank = u32::MAX;
    let mut best_nonce = 0u32;
    // The span's smallest digests by value, for step 3c, kept as a max-heap
    // so the largest of them is the one a smaller digest displaces.
    let mut smallest = std::collections::BinaryHeap::new();
    let hasher = HeaderHasher::new(header, Backend::detect());
    let target_words = sha256::target_words(target);
    for nonce in 0..span.min(u64::from(u32::MAX)) as u32 {
        let state = hasher.hash(nonce);
        if sha256::meets_target(&state, &target_words) {
            expected.push(nonce);
        }
        let rank = sha256::best_rank(&state);
        if rank < best_rank {
            best_rank = rank;
            best_nonce = nonce;
        }
        let value = value_words(&state);
        if smallest.len() < TIE_WINNERS {
            smallest.push((value, nonce));
        } else if smallest.peek().is_some_and(|largest| value < largest.0) {
            smallest.pop();
            smallest.push((value, nonce));
        }
    }

    let mut sorted = claimed.clone();
    sorted.sort_unstable();
    if sorted != expected {
        return Err(format!(
            "the GPU found {} winners over {span} nonces and the CPU found {}: {:?} against {:?}",
            sorted.len(),
            expected.len(),
            &sorted[..sorted.len().min(8)],
            &expected[..expected.len().min(8)],
        ));
    }
    if expected.is_empty() {
        return Err(
            "the winner comparison proved nothing: no nonce in the span met the target".into(),
        );
    }
    for nonce in &claimed {
        if !GpuMiner::verify(header, target, *nonce) {
            return Err(format!(
                "the GPU claimed nonce {nonce}, which rust-bitcoin rejects"
            ));
        }
    }
    log.log(format!(
        "probe: {} winners over {span} nonces, exactly matching the CPU",
        claimed.len()
    ));

    // 3b. The best hash of that same span, against the CPU's answer for it.
    //     The winner set says nothing about this: a dispatch can rank every
    //     digest it hashed and still record no winner, and the ranking is the
    //     only part of the shader that no other check here reaches.
    //
    //     The **rank** is compared rather than the nonce, because the rank is
    //     what the two devices compute and it is free of the one race the
    //     shader admits to — two lanes storing a nonce either side of the same
    //     atomic. The nonce is then checked for being real and for being worth
    //     what the rank says, which is what the run reports.
    if claimed_best != best_rank {
        return Err(format!(
            "the GPU ranks its best hash over {span} nonces {claimed_best:#010x}, the CPU {best_rank:#010x}"
        ));
    }
    let Some(claimed_best_nonce) = claimed_best_nonce else {
        return Err(format!(
            "the GPU reported no best nonce over {span} nonces; the CPU found {best_nonce}"
        ));
    };
    if sha256::best_rank(&hasher.hash(claimed_best_nonce)) != best_rank {
        return Err(format!(
            "the GPU calls nonce {claimed_best_nonce} its best over {span} nonces, which the CPU ranks below nonce {best_nonce}"
        ));
    }
    let mut best_header = *header;
    best_header.nonce = claimed_best_nonce;
    log.log(format!(
        "probe: both devices rank nonce {claimed_best_nonce} best over {span} nonces, at difficulty {:.6}",
        difficulty_of_hash(&best_header.block_hash()),
    ));

    // 3c. A tie on the top word, both ways. The search decides almost every
    //     nonce from word seven alone and hands a tie in it to the whole
    //     digest — a branch a random target reaches about once in 2^32
    //     nonces, so this one is built to reach it. The target is exactly
    //     the 1,000th-smallest digest's value: its top word is non-zero, and
    //     one nonce ties it.
    let (tied, tied_nonce) = *smallest.peek().ok_or("the probe span hashed no nonces")?;
    if tied[0] == 0 {
        return Err(format!(
            "the 1,000th-smallest digest over {span} nonces has a zero top word, so the tie \
             check would not be a tie on a non-zero one"
        ));
    }
    let at: Vec<u32> = ascending(smallest.iter().map(|(_, nonce)| *nonce).collect());
    let below: Vec<u32> = ascending(
        smallest
            .iter()
            .filter(|(_, nonce)| *nonce != tied_nonce)
            .map(|(_, nonce)| *nonce)
            .collect(),
    );
    for (name, target, expected) in [
        ("at", target_at(tied), at),
        ("one below", target_at(minus_one(tied)), below),
    ] {
        let claimed = miner.search(header, target, 0)?;
        if claimed.overflowed || ascending(claimed.nonces.clone()) != expected {
            return Err(format!(
                "with the target {name} nonce {tied_nonce}'s digest, the GPU found {} winners \
                 and the CPU {}",
                claimed.nonces.len(),
                expected.len()
            ));
        }
    }
    log.log(format!(
        "probe: a tie on the top word at nonce {tied_nonce} is decided both ways, as on the CPU"
    ));

    // 3d. A zero word seven, which no random digest reaches: the rank then
    //     comes from word six, through the whole digest. The genesis header's
    //     hash has 43 leading zero bits, so a span around its real nonce has
    //     one. Its own value as the target is also a tie on a zero top word.
    let (name, genesis) = &headers[1];
    let base = genesis.nonce - (span / 2) as u32;
    let state = HeaderHasher::new(genesis, Backend::detect()).hash(genesis.nonce);
    if state[7] != 0 {
        return Err(format!("{name} does not hash to a zero word seven"));
    }
    let value = value_words(&state);
    let targets = [("at", value), ("one below", minus_one(value))].map(|(label, words)| {
        (
            label,
            target_at(words),
            sha256::target_words(target_at(words)),
        )
    });

    // One CPU pass over the span answers both targets.
    let hasher = HeaderHasher::new(genesis, Backend::detect());
    let mut expected = [Vec::new(), Vec::new()];
    let mut best = u32::MAX;
    for nonce in base..base + span as u32 {
        let state = hasher.hash(nonce);
        for ((_, _, words), expected) in targets.iter().zip(&mut expected) {
            if sha256::meets_target(&state, words) {
                expected.push(nonce);
            }
        }
        best = best.min(sha256::best_rank(&state));
    }

    for ((label, target, _), expected) in targets.into_iter().zip(expected) {
        let claimed = miner.search(genesis, target, base)?;
        if ascending(claimed.nonces.clone()) != expected || claimed.best_rank != best {
            return Err(format!(
                "{name}, target {label} its own hash: the GPU found {:?} ranked best \
                 {:#010x}, the CPU {expected:?} ranked best {best:#010x}",
                claimed.nonces, claimed.best_rank
            ));
        }
    }
    log.log(format!(
        "probe: {name}'s zero word seven is ranked and judged exactly as on the CPU"
    ));

    // 4. The pipelined path against the one-shot path. Everything above went
    //    through `search`, which submits and waits; production overlaps
    //    dispatches instead. The failure this is here for is a slot mix-up,
    //    which would report one span's winners against another span's nonces —
    //    and which every check above would pass.
    let spans = 3u64;
    let mut expected = Vec::new();
    for step in 0..spans {
        let base = (step * span) as u32;
        expected.push((base, ascending(miner.search(header, target, base)?.nonces)));
    }

    let mut streamed = Vec::new();
    for step in 0..spans {
        let base = (step * span) as u32;
        if let Some(done) = miner.advance(header, target, base)? {
            streamed.push((done.base_nonce, ascending(done.winners.nonces)));
        }
    }
    if let Some(done) = miner.finish()? {
        streamed.push((done.base_nonce, ascending(done.winners.nonces)));
    }

    if streamed != expected {
        return Err(format!(
            "the pipelined path disagrees with the one-shot path: {:?} against {:?}",
            streamed
                .iter()
                .map(|(base, winners)| (base, winners.len()))
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|(base, winners)| (base, winners.len()))
                .collect::<Vec<_>>(),
        ));
    }
    log.log(format!(
        "probe: {spans} pipelined dispatches return exactly what {spans} one-shot searches do"
    ));

    // 5. The paired kernel, `search_pair`, held to the same standard.
    probe_pairs(miner, log, &headers, target, span)
}

/// Probe step 5: `search_pair` against the CPU, over one header under two
/// versions.
///
/// Its winner list is a nonce once per version that wins, so it is compared as
/// a list rather than a set. Its rare path — a tie on the top word, or a zero
/// one — reads one version's midstate, so 5d builds a zero word seven in each
/// position of the pair: the only way to tell a rare path that reads the wrong
/// midstate from one that reads the right one.
fn probe_pairs(
    miner: &mut GpuMiner,
    log: &crate::logger::Logger,
    headers: &[(&'static str, Header)],
    target: Target,
    span: u64,
) -> Result<(), String> {
    let rolled = |header: &Header| {
        let mut rolled = *header;
        rolled.version =
            bitcoin::block::Version::from_consensus(header.version.to_consensus() ^ (1 << 13));
        rolled
    };

    // 5a, 5b. The winner list and the best rank, over the probe span.
    let (name, header) = &headers[0];
    let pair = Headers::pair(*header, rolled(header))?;
    let hashers = pair
        .as_slice()
        .iter()
        .map(|header| HeaderHasher::new(header, Backend::detect()))
        .collect::<Vec<_>>();
    let target_words = sha256::target_words(target);
    let mut expected = Vec::new();
    let mut best = u32::MAX;
    let mut smallest = std::collections::BinaryHeap::new();
    for nonce in 0..span.min(u64::from(u32::MAX)) as u32 {
        for hasher in &hashers {
            let state = hasher.hash(nonce);
            if sha256::meets_target(&state, &target_words) {
                expected.push(nonce);
            }
            best = best.min(sha256::best_rank(&state));
            let value = value_words(&state);
            if smallest.len() < TIE_WINNERS {
                smallest.push((value, nonce));
            } else if smallest.peek().is_some_and(|largest| value < largest.0) {
                smallest.pop();
                smallest.push((value, nonce));
            }
        }
    }
    let expected = ascending(expected);

    let claimed = miner.search_headers(&pair, target, 0)?;
    if claimed.overflowed || ascending(claimed.nonces.clone()) != expected {
        return Err(format!(
            "{name} under two versions: the paired GPU search found {} winners over {span} \
             nonces and the CPU {}",
            claimed.nonces.len(),
            expected.len()
        ));
    }
    if expected.is_empty() {
        return Err("the paired winner comparison proved nothing: nothing met the target".into());
    }
    if claimed.best_rank != best {
        return Err(format!(
            "the paired GPU search ranks its best hash {:#010x}, the CPU {best:#010x}",
            claimed.best_rank
        ));
    }
    let best_nonce = claimed
        .best_nonce
        .ok_or("the paired GPU search reported no best nonce")?;
    if !hashers
        .iter()
        .any(|hasher| sha256::best_rank(&hasher.hash(best_nonce)) == best)
    {
        return Err(format!(
            "the paired GPU search calls nonce {best_nonce} its best, which ranks lower than \
             that under both versions"
        ));
    }
    log.log(format!(
        "probe: paired search, {} winners over two versions of {span} nonces and the best \
         rank, exactly matching the CPU",
        expected.len()
    ));

    // 5c. A tie on a non-zero top word, at the 1,000th-smallest digest across
    //     both versions, decided both ways.
    let (tied, tied_nonce) = *smallest.peek().ok_or("the paired probe hashed no nonces")?;
    if tied[0] == 0 {
        return Err("the paired tie check's digest has a zero top word".into());
    }
    let at = ascending(smallest.iter().map(|(_, nonce)| *nonce).collect());
    let below = ascending(
        smallest
            .iter()
            .filter(|(value, _)| *value != tied)
            .map(|(_, nonce)| *nonce)
            .collect(),
    );
    for (label, words, expected) in [("at", tied, at), ("one below", minus_one(tied), below)] {
        let claimed = miner.search_headers(&pair, target_at(words), 0)?;
        if claimed.overflowed || ascending(claimed.nonces.clone()) != expected {
            return Err(format!(
                "paired search, target {label} nonce {tied_nonce}'s digest: the GPU found {} \
                 winners and the CPU {}",
                claimed.nonces.len(),
                expected.len()
            ));
        }
    }
    log.log(format!(
        "probe: paired search decides a tie on the top word at nonce {tied_nonce} both ways"
    ));

    // 5d. A zero word seven in each position of the pair: the genesis header
    //     first, then second. The CPU's answer is the same for both orders,
    //     so one pass serves all four searches.
    let (name, genesis) = &headers[1];
    let other = rolled(genesis);
    let base = genesis.nonce - (span / 2) as u32;
    let value = value_words(&HeaderHasher::new(genesis, Backend::detect()).hash(genesis.nonce));
    let targets = [("at", value), ("one below", minus_one(value))];
    let hashers = [genesis, &other].map(|header| HeaderHasher::new(header, Backend::detect()));
    let mut expected = [Vec::new(), Vec::new()];
    let mut best = u32::MAX;
    for nonce in base..base + span as u32 {
        for hasher in &hashers {
            let state = hasher.hash(nonce);
            for ((_, words), expected) in targets.iter().zip(&mut expected) {
                // A digest's value words are already a target's words.
                if sha256::meets_target(&state, words) {
                    expected.push(nonce);
                }
            }
            best = best.min(sha256::best_rank(&state));
        }
    }

    for (position, pair) in [
        ("first", Headers::pair(*genesis, other)?),
        ("second", Headers::pair(other, *genesis)?),
    ] {
        for ((label, words), expected) in targets.iter().zip(&expected) {
            let claimed = miner.search_headers(&pair, target_at(*words), base)?;
            if ascending(claimed.nonces.clone()) != ascending(expected.clone())
                || claimed.best_rank != best
            {
                return Err(format!(
                    "{name} as the {position} of a pair, target {label} its own hash: the GPU \
                     found {:?} ranked best {:#010x}, the CPU {expected:?} ranked best {best:#010x}",
                    claimed.nonces, claimed.best_rank
                ));
            }
        }
    }
    log.log(format!(
        "probe: paired search judges and ranks {name}'s zero word seven in either position"
    ));

    // 5e. Pipelined pairs against one-shot pairs: the slot mix-up step 4 is
    //     for, under the other pipeline.
    let (_, header) = &headers[0];
    let pair = Headers::pair(*header, rolled(header))?;
    let spans = 3u64;
    let mut expected = Vec::new();
    for step in 0..spans {
        let base = (step * span) as u32;
        expected.push((
            base,
            ascending(miner.search_headers(&pair, target, base)?.nonces),
        ));
    }
    let mut streamed = Vec::new();
    for step in 0..spans {
        let base = (step * span) as u32;
        if let Some(done) = miner.advance_headers(&pair, target, base)? {
            streamed.push((done.base_nonce, ascending(done.winners.nonces)));
        }
    }
    if let Some(done) = miner.finish()? {
        streamed.push((done.base_nonce, ascending(done.winners.nonces)));
    }
    if streamed != expected {
        return Err("pipelined pair dispatches disagree with one-shot pair dispatches".into());
    }
    log.log(format!(
        "probe: {spans} pipelined pair dispatches return exactly what {spans} one-shot ones do"
    ));

    Ok(())
}

/// `miner.wgsl`, with the round functions it calls appended.
fn shader_source() -> String {
    let mut source = include_str!("miner.wgsl").to_owned();
    // The prefix, the first pass from round 4, the second pass's word seven,
    // and a whole compression; then `search_pair`'s shared first pass.
    for (states, first, last) in [(1, 0, 3), (1, 4, 64), (1, 0, 61), (1, 0, 64), (2, 4, 64)] {
        source.push_str(&unrolled_rounds(states, first, last));
    }
    source
}

/// The shader function `sha256_rounds_{first}_{last}`: rounds `first` up to
/// `last` of one compression, written out one round at a time. With `states`
/// above one it is `sha256_rounds_x{states}_{first}_{last}` instead, which runs
/// that many working states over one message schedule — AsicBoost's sharing,
/// for `search_pair` — and adds each round's `K + W` once for all of them.
/// One state produces exactly what it did before there were two.
///
/// **Why not a loop.** The shader's rounds were a loop until this was
/// measured: the same search at 445 MH/s as a loop and 2,395 MH/s
/// written out, on the RTX 4070 Laptop. A loop indexes its message window and
/// its round constants by the loop counter, and unless the driver unrolls it —
/// which this one did not — those indices are not constants, so the window and
/// the constant table live in per-invocation memory instead of registers.
/// Written out, every index is a constant: the window is sixteen named
/// variables, each round constant is a literal, and padding words that are
/// zero fold away.
///
/// Generated rather than committed because it is the same two lines 250-odd
/// times, and a copy that differs in one of them would be a hash that is
/// wrong only after that round. The probe is what checks the output.
fn unrolled_rounds(states: usize, first: usize, last: usize) -> String {
    use std::fmt::Write;

    // One state keeps the unsuffixed names it always had; several are told
    // apart by a suffix per state.
    let suffixes: Vec<String> = if states == 1 {
        vec![String::new()]
    } else {
        (0..states).map(|state| state.to_string()).collect()
    };

    let mut out = if states == 1 {
        format!(
            "\nfn sha256_rounds_{first}_{last}(state: array<u32, 8>, block: array<u32, 16>) -> array<u32, 8> {{\n"
        )
    } else {
        let parameters: String = suffixes
            .iter()
            .map(|s| format!("state{s}: array<u32, 8>, "))
            .collect();
        format!(
            "\nfn sha256_rounds_x{states}_{first}_{last}({parameters}block: array<u32, 16>) -> array<array<u32, 8>, {states}> {{\n"
        )
    };
    for s in &suffixes {
        writeln!(
            out,
            "    var a{s} = state{s}[0]; var b{s} = state{s}[1]; var c{s} = state{s}[2]; var d{s} = state{s}[3];"
        )
        .unwrap();
        writeln!(
            out,
            "    var e{s} = state{s}[4]; var f{s} = state{s}[5]; var g{s} = state{s}[6]; var h{s} = state{s}[7];"
        )
        .unwrap();
    }
    for index in 0..16 {
        writeln!(out, "    var w{index} = block[{index}];").unwrap();
    }
    out.push_str("    var t1: u32;\n    var t2: u32;\n");
    if states > 1 {
        out.push_str("    var kw: u32;\n");
    }

    for round in first..last {
        // The schedule as a rolling window of sixteen: word `round` replaces
        // word `round - 16`, from words `round - 15`, `- 7` and `- 2`.
        let slot = round % 16;
        if round >= 16 {
            writeln!(
                out,
                "    w{slot} = w{slot} + small_sigma0(w{}) + w{} + small_sigma1(w{});",
                (round + 1) % 16,
                (round + 9) % 16,
                (round + 14) % 16
            )
            .unwrap();
        }
        let constant = if states == 1 {
            format!("{:#010x}u + w{slot}", sha256::K[round])
        } else {
            writeln!(out, "    kw = {:#010x}u + w{slot};", sha256::K[round]).unwrap();
            "kw".to_owned()
        };
        for s in &suffixes {
            writeln!(
                out,
                "    t1 = h{s} + big_sigma1(e{s}) + ((e{s} & f{s}) ^ (~e{s} & g{s})) + {constant}; \
                 t2 = big_sigma0(a{s}) + ((a{s} & b{s}) ^ (a{s} & c{s}) ^ (b{s} & c{s})); \
                 h{s} = g{s}; g{s} = f{s}; f{s} = e{s}; e{s} = d{s} + t1; d{s} = c{s}; \
                 c{s} = b{s}; b{s} = a{s}; a{s} = t1 + t2;"
            )
            .unwrap();
        }
    }

    let returned: Vec<String> = suffixes
        .iter()
        .map(|s| format!("array<u32, 8>(a{s}, b{s}, c{s}, d{s}, e{s}, f{s}, g{s}, h{s})"))
        .collect();
    if states == 1 {
        writeln!(out, "    return {};\n}}", returned[0]).unwrap();
    } else {
        writeln!(
            out,
            "    return array<array<u32, 8>, {states}>({});\n}}",
            returned.join(", ")
        )
        .unwrap();
    }
    out
}

fn ascending(mut nonces: Vec<u32>) -> Vec<u32> {
    nonces.sort_unstable();
    nonces
}

/// How many winners probe step 3c's tie target admits: enough that the tied
/// digest's top word is non-zero, well inside the winner buffer.
const TIE_WINNERS: usize = 1_000;

/// A digest's value as eight words, most significant first: the order a
/// target is written in, and the order that sorts digests by value.
fn value_words(state: &[u32; 8]) -> [u32; 8] {
    std::array::from_fn(|index| state[7 - index].swap_bytes())
}

/// The target whose value is these words.
fn target_at(words: [u32; 8]) -> Target {
    let mut bytes = [0u8; 32];
    for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    Target::from_be_bytes(bytes)
}

/// One less, as a 256-bit number.
fn minus_one(mut words: [u32; 8]) -> [u32; 8] {
    for word in words.iter_mut().rev() {
        let borrowed = *word == 0;
        *word = word.wrapping_sub(1);
        if !borrowed {
            break;
        }
    }
    words
}

/// Headers the probe hashes.
///
/// The synthetic one has every field distinct, so a byte-order mistake
/// anywhere in the 80 bytes changes the digest. The genesis header is the
/// check that matters more: its hash is a published constant, so agreeing with
/// it is agreement with something outside this repository rather than with
/// another of its own implementations.
fn probe_headers() -> Vec<(&'static str, Header)> {
    use bitcoin::{
        BlockHash, CompactTarget, Network, TxMerkleNode,
        block::{Header, Version},
        blockdata::constants::genesis_block,
        hashes::Hash,
    };

    let synthetic = Header {
        version: Version::from_consensus(0x2000_0000),
        prev_blockhash: BlockHash::from_byte_array([0x11; 32]),
        merkle_root: TxMerkleNode::from_byte_array([0x22; 32]),
        time: 0x3344_5566,
        bits: CompactTarget::from_consensus(0x1702_3ad4),
        nonce: 0,
    };

    vec![
        ("a synthetic header", synthetic),
        (
            "the mainnet genesis header",
            genesis_block(Network::Bitcoin).header,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pair_is_one_header_under_two_versions_and_nothing_else() {
        let (_, header) = probe_headers()[0];
        let mut rolled = header;
        rolled.version = bitcoin::block::Version::from_consensus(0x2000_2000);
        assert!(Headers::pair(header, rolled).is_ok());

        // The same version twice is not a pair.
        assert!(Headers::pair(header, header).is_err());

        // Anything else different would hash one header and report another.
        let mut moved = rolled;
        moved.time += 1;
        assert!(Headers::pair(header, moved).is_err());
        let mut other_nonce = rolled;
        other_nonce.nonce += 1;
        assert!(Headers::pair(header, other_nonce).is_err());
    }

    #[test]
    fn the_paired_rounds_share_one_schedule_between_two_states() {
        let pair = unrolled_rounds(2, 4, 64);
        let rounds = 64 - 4;
        let schedule_words = 64 - 16;
        // One schedule extension and one `K + W` per round, two round updates.
        assert_eq!(pair.matches("w0 = w0 +").count(), 3);
        assert_eq!(
            pair.lines()
                .filter(|line| line.contains("small_sigma0"))
                .count(),
            schedule_words
        );
        assert_eq!(pair.matches("    kw = ").count(), rounds);
        assert_eq!(pair.matches("t1 = h0 +").count(), rounds);
        assert_eq!(pair.matches("t1 = h1 +").count(), rounds);
        assert!(pair.contains("fn sha256_rounds_x2_4_64(state0: array<u32, 8>, state1: array<u32, 8>, block: array<u32, 16>) -> array<array<u32, 8>, 2>"));

        // One state is the function `search` has always used, with no suffix.
        let single = unrolled_rounds(1, 4, 64);
        assert!(single.contains(
            "fn sha256_rounds_4_64(state: array<u32, 8>, block: array<u32, 16>) -> array<u32, 8>"
        ));
        assert!(!single.contains("kw"));
        assert_eq!(single.matches("t1 = h +").count(), rounds);
    }

    #[test]
    fn a_full_duty_cycle_builds_no_throttle_at_all() {
        assert!(Duty::new(100).is_none());
    }

    #[test]
    fn a_rest_is_in_proportion_to_the_work_behind_it() {
        let busy = Duration::from_millis(800);
        let rest = |percent| Duty::new(percent).expect("throttled").rest_for(busy);

        assert_eq!(rest(50), busy);
        assert_eq!(rest(80), Duration::from_millis(200));
        assert_eq!(rest(10), Duration::from_millis(7_200));
        // Whatever the overshoot past the window, the share still comes out
        // at what was asked for.
        let duty = Duty::new(75).expect("throttled");
        assert!(busy > duty.work);
        let share = busy.as_secs_f64() / (busy + duty.rest_for(busy)).as_secs_f64();
        assert!((share - 0.75).abs() < 1e-9, "{share}");
    }

    #[test]
    fn a_duty_cycle_outside_1_to_100_is_refused() {
        let config = |load_percent| GpuConfig {
            lanes: 262_144,
            nonces_per_lane: 256,
            capacity: 4_096,
            pipeline: 2,
            load_percent,
        };
        assert!(config(0).validate().is_err());
        assert!(config(101).validate().is_err());
        assert!(config(1).validate().is_ok());
        assert!(config(100).validate().is_ok());
    }

    /// Version rolling on the solo search, end to end: the block search over a
    /// regtest template with `testdummy` listed. Every block passes
    /// `check_block` and `rust-bitcoin`; with rolling on, blocks are found
    /// under both members of the first pair and nothing else, and with rolling
    /// off only under the template's version. Run by hand, since it needs a
    /// GPU:
    ///
    /// ```sh
    /// cargo test --release gpu::tests::the_block_search -- --ignored --nocapture
    /// ```
    ///
    /// **Both members are only seen at a target where winners are sparse.** At
    /// regtest's own target half of all hashes win, and the shader's lanes run
    /// in lockstep, each recording its first version's winner before its
    /// second's — so the buffer's first slot is the template's version all but
    /// always, and that is the nonce `claim` takes. Every one is still a block.
    /// So the regtest target checks validity, and a harder one — about one
    /// winner in eight dispatches — checks attribution, where the first winner
    /// is equally likely to be either version.
    #[test]
    #[ignore = "needs a GPU"]
    fn the_block_search_finds_blocks_under_both_versions_of_a_pair() {
        let value = serde_json::from_str(include_str!(
            "../tests/fixtures/template-regtest-145-testdummy.json"
        ))
        .expect("the capture should be JSON");
        let template = Template::parse(&value).expect("the capture should parse");
        let payout = ScriptBuf::from_hex("0014329649f03db93aef2cf873e9b8544a446d38316d")
            .expect("the payout should be hex");
        let mut miner = GpuMiner::new(GpuConfig {
            lanes: 4_096,
            nonces_per_lane: 64,
            capacity: 4_096,
            pipeline: 2,
            load_percent: 100,
        })
        .expect("a GPU");

        let mask = template.rollable_bits();
        assert_eq!(mask, 0x0fff_e000, "bit 28 is testdummy's");
        let announced = template.version as u32;
        // 2^-22 per hash: 0x03ffff * 2^216 is about 2^234.
        let sparse = Target::from_compact(bitcoin::CompactTarget::from_consensus(0x1e03_ffff));

        let mut versions = |mask: u32, target: Target| {
            let mut template = template.clone();
            template.target = target;
            let mut seen = std::collections::BTreeMap::<u32, usize>::new();
            for start in 0..64 {
                let search = search(
                    &template,
                    &payout,
                    &mut miner,
                    &Signals::unwatched(),
                    Extranonce(start),
                    mask,
                )
                .expect("a block search");
                let block = search.winner.expect("a search ends on a block").block;
                assert!(crate::block::meets_target(&block.header, target));
                crate::block::check_block(&block, &template).expect("the local checks");
                *seen
                    .entry(block.header.version.to_consensus() as u32)
                    .or_default() += 1;
            }
            println!(
                "mask {mask:08x}, target {:08x}: {:?}",
                target.to_compact_lossy().to_consensus(),
                seen.iter()
                    .map(|(version, count)| format!("{version:08x} x {count}"))
                    .collect::<Vec<_>>()
            );
            seen.into_keys().collect::<Vec<_>>()
        };

        let pair = vec![announced, announced | 1 << 13];
        let regtest = versions(mask, template.target);
        assert!(regtest.iter().all(|version| pair.contains(version)));
        assert_eq!(
            versions(mask, sparse),
            pair,
            "both members of the first pair"
        );
        assert_eq!(versions(0, template.target), vec![announced]);
        assert_eq!(versions(0, sparse), vec![announced]);
    }
}
