#!/usr/bin/env python3
import json
import sys
import os

def create_jit_file(name, size, url, output_dir="."):
    """
    Creates a .jit file with the given metadata.
    
    Args:
        name (str): The name of the file (e.g., "video.mp4")
        size (int): The size of the file in bytes
        url (str): The download URL (magnet, http, etc.)
        output_dir (str): Directory to save the .jit file
    """
    data = {
        "name": name,
        "size": int(size),
        "url": url
    }
    
    # Output filename is usually "original_name.jit"
    filename = f"{name}.jit"
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    
    print(f"Successfully created: {filepath}")
    print("Content:")
    print(json.dumps(data, indent=4, ensure_ascii=False))

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 gen_jit.py <filename> <size_in_bytes> <url> [output_dir]")
        print("Example: python3 gen_jit.py 'movie.mp4' 1024000 'magnet:?xt=urn:btih:...'")
        sys.exit(1)
        
    name = sys.argv[1]
    size = sys.argv[2]
    url = sys.argv[3]
    output_dir = sys.argv[4] if len(sys.argv) > 4 else "."
    
    create_jit_file(name, size, url, output_dir)
