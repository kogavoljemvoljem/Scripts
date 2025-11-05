import os
import shutil

def flatten_folder(source_dir, target_dir):
    # Create target directory if it doesn't exist
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
    
    # Dictionary to track file names and their counts
    file_counts = {}
    
    # Walk through all subfolders
    for root, _, files in os.walk(source_dir):
        for filename in files:
            # Skip files already in target directory
            if root == target_dir:
                continue
                
            source_path = os.path.join(root, filename)
            base, ext = os.path.splitext(filename)
            
            # Initialize new filename
            new_filename = filename
            counter = file_counts.get(filename, 0)
            
            # Check if file already exists in target
            while os.path.exists(os.path.join(target_dir, new_filename)):
                counter += 1
                new_filename = f"{base}_{counter}{ext}"
            
            # Update file counts
            file_counts[filename] = counter
            
            # Move and rename file
            target_path = os.path.join(target_dir, new_filename)
            shutil.move(source_path, target_path)
            print(f"Moved: {filename} -> {new_filename}")

# Usage
source_directory = "C:/users/admin/pictures"  # Replace with your source folder path
target_directory = "D:/Media"  # Replace with your target folder path

flatten_folder(source_directory, target_directory)
