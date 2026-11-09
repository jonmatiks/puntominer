# Contributing

PuntoMiner is an experimental, educational project maintained on a best-effort
basis. As the [README's disclaimer](README.md#no-obligation-software-disclaimer)
says, there is no obligation to answer issues, review pull requests, or keep
any behaviour stable between versions. Contributions are still welcome.

## Reporting a problem

Open an issue with:

- the command you ran (replace any address you would rather not share),
- the relevant lines from `results/log`,
- your OS, CPU, GPU and graphics driver, and your Rust and Bitcoin Core
  versions.

Never paste the contents of your node's `.cookie` file. It is the node's RPC
credential.

## Proposing a change

1. Read the [developer guide](docs/developer-guide.md) and the rules in
   [AGENTS.md](AGENTS.md). Most of those rules exist because breaking them
   produced a wrong answer that looked like a right one.
2. Keep the change small, and to one concern per pull request.
3. Run `cargo fmt --check`, `cargo clippy --all-targets` and `cargo test`. If
   you touched the GPU path, the long-poll or a pool client, also run the
   matching smoke test from the developer guide.
4. Add an entry at the top of the `Unreleased` section of
   [CHANGELOG.md](CHANGELOG.md).
5. Quote any hash rate with its hasher, device and CPU clock.

## License

By contributing, you agree that your contribution is licensed under the
[MIT License](LICENSE).
