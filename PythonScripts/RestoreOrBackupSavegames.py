import os
import shutil

# Common savegame directories
COMMON_SAVE_LOCATIONS = [
    r"C:\Users\%USERNAME%\Documents\My Games",
    r"C:\Users\%USERNAME%\Saved Games",
    r"C:\Users\%USERNAME%\AppData\Local",
    r"C:\Users\%USERNAME%\AppData\Roaming"
]

def resolve_environment_variables(path):
    """Expand environment variables like %USERNAME% in paths."""
    return os.path.expandvars(path)

def backup_saves():
    print("=== Savegame Backup ===")
    backup_dir = input("Enter the destination folder for the backup: ").strip()
    os.makedirs(backup_dir, exist_ok=True)

    for save_location in COMMON_SAVE_LOCATIONS:
        resolved_path = resolve_environment_variables(save_location)

        if not os.path.exists(resolved_path):
            print(f"Directory not found: {resolved_path}")
            continue

        # Create a backup folder for this directory
        dest_dir = os.path.join(backup_dir, os.path.basename(resolved_path))
        os.makedirs(dest_dir, exist_ok=True)

        print(f"Backing up: {resolved_path} -> {dest_dir}")
        try:
            shutil.copytree(resolved_path, dest_dir, dirs_exist_ok=True)
        except Exception as e:
            print(f"Error copying {resolved_path}: {e}")

    print(f"Backup completed! All save files are in {backup_dir}")

def restore_saves():
    print("=== Savegame Restore ===")
    backup_dir = input("Enter the folder where your savegame backup is located: ").strip()

    if not os.path.exists(backup_dir):
        print(f"Backup directory not found: {backup_dir}")
        return

    for root, dirs, _ in os.walk(backup_dir):
        for dir_name in dirs:
            backup_path = os.path.join(root, dir_name)
            original_path = resolve_environment_variables(dir_name)

            if os.path.exists(original_path):
                print(f"Restoring: {backup_path} -> {original_path}")
                try:
                    shutil.copytree(backup_path, original_path, dirs_exist_ok=True)
                except Exception as e:
                    print(f"Error restoring {backup_path}: {e}")
            else:
                print(f"Original path not found, creating: {original_path}")
                os.makedirs(original_path, exist_ok=True)
                shutil.copytree(backup_path, original_path, dirs_exist_ok=True)

    print("Restore completed!")

if __name__ == "__main__":
    print("1. Backup savegames")
    print("2. Restore savegames")
    choice = input("Enter your choice (1/2): ").strip()

    if choice == "1":
        backup_saves()
    elif choice == "2":
        restore_saves()
    else:
        print("Invalid choice! Exiting...")
