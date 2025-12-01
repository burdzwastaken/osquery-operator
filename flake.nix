{
  description = "osquery-operator";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            git
            go
            gopls
            gotools
            kubectl
            minikube
            podman
          ];

          shellHook = ''
            echo "osquery-operator development environment loaded!"
            echo ""
            echo "dev tools:"
            echo "  go version: $(go version)"
            echo "  golangci-lint version: $(go tool golangci-lint --version)"
            echo ""
            echo "kubernetes tools:"
            echo "  kubectl version: $(kubectl version --client -o json 2>/dev/null | jq -r '.clientVersion.gitVersion')"
            echo "  minikube version: $(minikube version --short)"
            echo ""
            echo "container tools:"
            echo "  podman version: $(podman --version | cut -d' ' -f3)"
            echo ""
            echo "module: github.com/burdzwastaken/osquery-operator"
            echo ""
          '';
        };
      }
    );
}
