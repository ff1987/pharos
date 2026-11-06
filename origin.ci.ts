// Native Origin CI for this Origin-owned repository.
// Linux only: Origin's documented runners do not list macOS or Windows.
// macOS and Windows are in .github/workflows/ci.yml.
const linux = {
  image: "rust:bookworm",
  platform: { disk: "32Gi" },
  inputs: ["**"],
  steps: [
    { name: "Test and release build", command: "bash scripts/ci.sh" },
  ],
};

export default {
  jobs: {
    linux,
  },
};
