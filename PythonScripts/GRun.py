import os
import platform
import subprocess
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Function to detect the file type based on extension
def detect_file_type(file_path):
    extension = os.path.splitext(file_path)[1].lower()
    if extension == ".exe":
        return "windows"
    elif extension in [".sh", ".bin"]:
        return "linux"
    elif extension == ".app":
        return "macos"
    return None

# Function to install dependencies (Wine and Docker)
def install_dependencies():
    try:
        if platform.system() != "Windows":
            subprocess.run(["which", "wine"], check=True)
        subprocess.run(["which", "docker"], check=True)
    except subprocess.CalledProcessError:
        print("Installing dependencies (Wine and Docker)...")
        if platform.system() == "Linux":
            subprocess.run(["sudo", "apt-get", "update"])
            subprocess.run(["sudo", "apt-get", "install", "-y", "wine", "docker.io"])
        elif platform.system() == "Darwin":
            subprocess.run(["brew", "install", "wine", "docker"])
        else:
            print("Please install Wine and Docker manually.")

# Function to set up Wine dependencies for Windows games
def setup_wine_dependencies():
    try:
        subprocess.run(["wine", "--version"], check=True)
    except subprocess.CalledProcessError:
        print("Wine is not installed. Please install Wine to run Windows games.")
        return

# Function to create and run a Docker container
def create_docker_container(file_path, file_type):
    try:
        if file_type == "windows":
            image = "wine:latest"
            command = f"wine /game/{os.path.basename(file_path)}"
        elif file_type == "linux":
            image = "ubuntu:latest"
            command = f"/game/{os.path.basename(file_path)}"
        elif file_type == "macos":
            print("macOS sandboxing is not supported yet.")
            return
        else:
            print("Docker support for this OS type is not yet implemented.")
            return

        subprocess.run([
            "docker", "run", "--rm", "-v", f"{os.path.abspath(file_path)}:/game/{os.path.basename(file_path)}", image, "bash", "-c", command
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running game in Docker: {e}")

# Function to run the game
def run_game(file_path, file_type):
    try:
        if file_type == "windows" and platform.system() != "Windows":
            setup_wine_dependencies()
            create_docker_container(file_path, file_type)
        elif file_type == "linux" and platform.system() != "Linux":
            create_docker_container(file_path, file_type)
        elif file_type == "windows" and platform.system() == "Windows":
            subprocess.Popen([file_path], shell=True)
        elif file_type == "macos":
            if platform.system() == "Darwin":
                subprocess.Popen(["open", file_path], shell=True)
            else:
                print("macOS games are not supported outside macOS yet.")
        elif file_type == "linux":
            subprocess.Popen([file_path], shell=True)
        else:
            print("Unsupported file type.")
    except Exception as e:
        print(f"Error running game: {e}")

# Event handler class to handle file creation (new executable files)
class GameFileHandler(FileSystemEventHandler):
    def __init__(self):
        self.is_running = False

    def on_created(self, event):
        if event.is_directory:
            return  # Ignore directories
        print(f"Detected new file: {event.src_path}")
        
        file_type = detect_file_type(event.src_path)
        if file_type:
            print(f"Detected file type: {file_type}")
            run_game(event.src_path, file_type)

    def on_modified(self, event):
        if event.is_directory:
            return  # Ignore directories
        print(f"Modified file: {event.src_path}")
        
        file_type = detect_file_type(event.src_path)
        if file_type:
            print(f"Detected file type: {file_type}")
            run_game(event.src_path, file_type)

# Main function to watch the directory
def watch_directory(directory_to_watch):
    event_handler = GameFileHandler()
    observer = Observer()
    observer.schedule(event_handler, directory_to_watch, recursive=True)
    observer.start()
    print(f"Watching directory: {directory_to_watch}")

    try:
        while True:
            time.sleep(1)  # Sleep and keep the program running
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    install_dependencies()  # Make sure dependencies are installed
    directory_to_watch = input("Enter the directory to watch for executables: ")
    print(f"Starting to watch {directory_to_watch} for new executable files...")
    watch_directory(directory_to_watch)