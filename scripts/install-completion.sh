#!/bin/bash

# Installation script for obfuskit auto-completion

set -e

# Detect shell
SHELL_NAME=$(basename "$SHELL")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing obfuskit auto-completion for $SHELL_NAME..."

case "$SHELL_NAME" in
    bash)
        # Check if bash-completion is available
        if ! command -v brew &> /dev/null || ! brew list bash-completion &> /dev/null 2>&1; then
            echo "Note: bash-completion is not installed. You may want to install it first:"
            echo "  brew install bash-completion"
        fi
        
        # Install bash completion
        COMPLETION_DIR="/usr/local/etc/bash_completion.d"
        if [[ -d "$COMPLETION_DIR" ]]; then
            sudo cp "$SCRIPT_DIR/completion.bash" "$COMPLETION_DIR/obfuskit"
            echo "✅ Installed bash completion to $COMPLETION_DIR/obfuskit"
        else
            echo "Warning: $COMPLETION_DIR not found. You can manually source the completion:"
            echo "  echo 'source $SCRIPT_DIR/completion.bash' >> ~/.bashrc"
        fi
        ;;
        
    zsh)
        # Install zsh completion
        ZSH_COMPLETION_DIR="/usr/local/share/zsh/site-functions"
        if [[ -d "$ZSH_COMPLETION_DIR" ]]; then
            sudo cp "$SCRIPT_DIR/completion.zsh" "$ZSH_COMPLETION_DIR/_obfuskit"
            echo "✅ Installed zsh completion to $ZSH_COMPLETION_DIR/_obfuskit"
        else
            # Try user-specific directory
            USER_ZSH_DIR="$HOME/.zsh/completions"
            mkdir -p "$USER_ZSH_DIR"
            cp "$SCRIPT_DIR/completion.zsh" "$USER_ZSH_DIR/_obfuskit"
            echo "✅ Installed zsh completion to $USER_ZSH_DIR/_obfuskit"
            echo "Make sure to add the following to your ~/.zshrc if not already present:"
            echo "  fpath=(~/.zsh/completions \$fpath)"
            echo "  autoload -U compinit && compinit"
        fi
        ;;
        
    fish)
        echo "Fish shell completion not yet implemented."
        echo "Please contribute at: https://github.com/your-repo/obfuskit"
        ;;
        
    *)
        echo "Unsupported shell: $SHELL_NAME"
        echo "Supported shells: bash, zsh"
        exit 1
        ;;
esac

echo ""
echo "Auto-completion installed! Restart your shell or run:"
case "$SHELL_NAME" in
    bash)
        echo "  source ~/.bashrc"
        ;;
    zsh)
        echo "  source ~/.zshrc"
        ;;
esac

echo ""
echo "Test completion by typing: obfuskit -<TAB>"
