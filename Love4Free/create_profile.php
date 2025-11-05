<?php
session_start();
include 'db.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['name'] ?? '';
    $bio = $_POST['bio'] ?? '';
    $song = $_POST['song'] ?? '';
    $personality = $_POST['personality'] ?? '';
    $job = $_POST['job'] ?? '';
    $hobbies = $_POST['hobbies'] ?? '';
    $love = $_POST['love'] ?? '';
    $travel = $_POST['travel'] ?? '';
    $video = $_POST['video'] ?? '';
    $notes = $_POST['notes'] ?? '';
    $avatar = $_POST['avatar'] ?? '';
    $song_type = '';

    if (!empty($video) && strpos($video, 'youtube.com') !== false) {
        $video = preg_replace(
            "/\s*[a-zA-Z\/\/:\.]*youtube.com\/watch\?v=([a-zA-Z0-9\-_]+)([a-zA-Z0-9\/\*\-\_\?\&\;\%\=\.]*)/i",
            "https://www.youtube.com/embed/$1",
            $video
        );
    }
    
    if (!empty($song)) {
        if (strpos($song, 'spotify.com') !== false) {
            $song_type = 'spotify';
            $song = basename(parse_url($song, PHP_URL_PATH));
        } elseif (strpos($song, 'youtube.com') !== false) {
            $song_type = 'youtube';
            $song = preg_replace(
                "/\s*[a-zA-Z\/\/:\.]*youtube.com\/watch\?v=([a-zA-Z0-9\-_]+)([a-zA-Z0-9\/\*\-\_\?\&\;\%\=\.]*)/i",
                "https://www.youtube.com/embed/$1",
                $song
            );
        }
    }

    $stmt = $pdo->prepare("INSERT INTO profiles (name, bio, song, song_type, personality, job, hobbies, love, travel, video, notes, avatar) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->execute([$name, $bio, $song, $song_type, $personality, $job, $hobbies, $love, $travel, $video, $notes, $avatar]);

    $_SESSION['user_id'] = $pdo->lastInsertId();
    $_SESSION['posts'] = [];
    
    header("Location: index.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Create Your Profile - Love4Free</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen p-4">
  <div class="max-w-2xl mx-auto bg-gray-800 p-6 rounded-lg">
    <h1 class="text-2xl font-bold mb-6">Create Your Dating Profile</h1>
    
    <form method="POST" class="space-y-4">
      <div>
        <label class="block mb-2 font-medium">Your Name</label>
        <input type="text" name="name" required 
               class="w-full p-3 bg-gray-700 rounded">
      </div>
      <div>
        <label class="block mb-2 font-medium">Avatar URL (e.g., Imgur link)</label>
        <input type="text" name="avatar" placeholder="https://i.imgur.com/..." 
               class="w-full p-3 bg-gray-700 rounded">
      </div>
      <div>
        <label class="block mb-2 font-medium">Bio (Tell us about yourself)</label>
        <textarea name="bio" rows="3" required
                  class="w-full p-3 bg-gray-700 rounded"></textarea>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label class="block mb-2 font-medium">Personality Type</label>
          <input type="text" name="personality" 
                 placeholder="e.g., INFP, Extrovert"
                 class="w-full p-3 bg-gray-700 rounded">
        </div>
        <div>
          <label class="block mb-2 font-medium">Occupation</label>
          <input type="text" name="job" 
                 class="w-full p-3 bg-gray-700 rounded">
        </div>
      </div>
      <div>
        <label class="block mb-2 font-medium">Favorite Song (URL or name)</label>
        <input type="text" name="song" 
               placeholder="Spotify or YouTube link, or song name"
               class="w-full p-3 bg-gray-700 rounded">
      </div>
      <div>
        <label class="block mb-2 font-medium">Video Introduction (YouTube URL)</label>
        <input type="text" name="video" 
               placeholder="https://www.youtube.com/watch?v=..."
               class="w-full p-3 bg-gray-700 rounded">
      </div>
      <div>
        <label class="block mb-2 font-medium">Hobbies & Interests</label>
        <textarea name="hobbies" rows="2"
                  class="w-full p-3 bg-gray-700 rounded"></textarea>
      </div>
      <div>
        <label class="block mb-2 font-medium">What You're Looking For</label>
        <textarea name="love" rows="2"
                  class="w-full p-3 bg-gray-700 rounded"></textarea>
      </div>
      <div>
        <label class="block mb-2 font-medium">Travel Preferences</label>
        <input type="text" name="travel" 
               placeholder="e.g., Beach lover, Mountain hiker"
               class="w-full p-3 bg-gray-700 rounded">
      </div>
      <div>
        <label class="block mb-2 font-medium">Private Notes (only you can see)</label>
        <textarea name="notes" rows="2"
                  class="w-full p-3 bg-gray-700 rounded"></textarea>
      </div>
      <button type="submit" 
              class="w-full py-3 bg-purple-600 rounded-lg hover:bg-purple-700 font-medium">
        Create Profile
      </button>
    </form>
  </div>
</body>
</html>