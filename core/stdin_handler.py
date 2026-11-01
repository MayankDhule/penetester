"""
Stdin Handler - Read Targets from Standard Input
Enables piping targets from files or other tools
"""
import sys
from typing import List, Generator


class StdinHandler:
    """Handles reading targets from stdin"""
    
    @staticmethod
    def is_stdin_available() -> bool:
        """Check if stdin has data available"""
        return not sys.stdin.isatty()
    
    @staticmethod
    def read_targets() -> List[str]:
        """Read all targets from stdin"""
        if not StdinHandler.is_stdin_available():
            return []
        
        targets = []
        for line in sys.stdin:
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith('#'):
                targets.append(line)
        
        return targets
    
    @staticmethod
    def stream_targets() -> Generator[str, None, None]:
        """Stream targets from stdin one at a time (memory efficient)"""
        if not StdinHandler.is_stdin_available():
            return
        
        for line in sys.stdin:
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith('#'):
                yield line
    
    @staticmethod
    def read_target_or_stdin(target_arg: str = None) -> List[str]:
        """Read target from argument or stdin"""
        # If target provided as argument, use it
        if target_arg:
            return [target_arg]
        
        # Otherwise, try to read from stdin
        if StdinHandler.is_stdin_available():
            return StdinHandler.read_targets()
        
        # No target provided
        return []
    
    @staticmethod
    def validate_targets(targets: List[str]) -> List[str]:
        """Validate and clean targets"""
        import re
        
        valid_targets = []
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        for target in targets:
            # Remove protocol if present
            clean_target = target.replace('http://', '').replace('https://', '').split('/')[0]
            
            # Validate
            if re.match(domain_pattern, clean_target) or re.match(ip_pattern, clean_target):
                valid_targets.append(clean_target)
            elif target.startswith('http://') or target.startswith('https://'):
                # Allow full URLs
                valid_targets.append(target)
        
        return valid_targets


# Example usage documentation
STDIN_EXAMPLES = r"""
# Stdin Usage Examples

## Read targets from file
cat targets.txt | pentestrr scan

## Read from command output
echo "example.com" | pentestrr scan

## Multiple targets
cat << EOF | pentestrr scan --jsonl
example.com
test.com
demo.com
EOF

## From subdomain enumeration
subfinder -d example.com | pentestrr scan --jsonl

## From other tools
amass enum -d example.com | pentestrr scan --async

## Filter and scan
cat domains.txt | grep "\.com$" | pentestrr scan --jsonl

## Parallel scanning (GNU parallel)
cat targets.txt | parallel -j 5 pentestrr scan {} --jsonl

## With custom wordlists
cat targets.txt | pentestrr scan --dir-wordlist custom.txt

## Target file format
# targets.txt:
example.com
test.example.com
192.168.1.1
https://api.example.com

# Comments are ignored
# subdomain.example.com

## Streaming mode (process as they come)
tail -f live-targets.txt | pentestrr scan --jsonl

## Integration with other tools
# Discover subdomains, then scan
subfinder -d example.com | \
  httpx -silent | \
  pentestrr scan --async --jsonl | \
  jq 'select(.type == "vulnerability")'
"""
