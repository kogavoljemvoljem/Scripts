<?php
session_start();
include 'db.php';

if (!isset($_SESSION['posts'])) {
    $_SESSION['posts'] = [];
}

$cooldownPeriod = 30;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['content'])) {
    if (isset($_SESSION['user_id'])) {
        $stmt = $pdo->prepare("SELECT id, name, avatar FROM profiles WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            $currentTime = time();
            $content = trim($_POST['content']);

            if (!isset($_SESSION['last_post_time'])) {
                $_SESSION['last_post_time'] = 0;
            }
            if (!isset($_SESSION['last_post_content'])) {
                $_SESSION['last_post_content'] = '';
            }

            $timeSinceLastPost = $currentTime - $_SESSION['last_post_time'];
            if ($timeSinceLastPost < $cooldownPeriod) {
                $error = "Please wait " . ($cooldownPeriod - $timeSinceLastPost) . " seconds before posting again.";
            } elseif ($content === $_SESSION['last_post_content']) {
                $error = "You cannot post the same message twice in a row.";
            } elseif (!empty($content)) {
                $_SESSION['posts'][] = [
                    'id' => uniqid(),
                    'profile_id' => $user['id'], // Added profile_id
                    'user' => $user['name'],
                    'avatar' => $user['avatar'],
                    'content' => $content,
                    'time' => date('H:i')
                ];
                $_SESSION['last_post_time'] = $currentTime;
                $_SESSION['last_post_content'] = $content;
                $success = "Post added successfully!";
            } else {
                $error = "Post content cannot be empty.";
            }
        } else {
            $error = "User profile not found.";
        }
    } else {
        $error = "You must be logged in to post.";
    }
}

$userProfile = null;
if (isset($_SESSION['user_id'])) {
    $stmt = $pdo->prepare("SELECT * FROM profiles WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $userProfile = $stmt->fetch(PDO::FETCH_ASSOC);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Love4Free - Your Spotlight</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .player-container { height: calc(100vh - 4rem); }
    .posts-container { height: calc(100vh - 8rem); }
  </style>
</head>
<body class="bg-gray-900 text-white flex h-screen overflow-hidden">
  <!-- Music Player Sidebar -->
  <div class="w-64 p-4 bg-gray-800 flex flex-col player-container">
    <h2 class="text-xl font-bold mb-4">Now Playing</h2>
    <div id="player-content" class="flex-1">
      <?php if ($userProfile): ?>
        <?php if ($userProfile['avatar']): ?>
          <img src="<?php echo htmlspecialchars($userProfile['avatar']); ?>" alt="Avatar" class="w-16 h-16 rounded-full mb-4">
        <?php endif; ?>
        <?php if ($userProfile['song']): ?>
          <?php if ($userProfile['song_type'] === 'spotify'): ?>
            <iframe src="https://open.spotify.com/embed/track/<?php echo basename($userProfile['song']); ?>" 
                    width="100%" height="80" frameborder="0" allowtransparency="true" 
                    allow="encrypted-media" class="mb-4"></iframe>
          <?php else: ?>
            <p class="text-gray-300 mb-2"><?php echo $userProfile['song']; ?></p>
          <?php endif; ?>
        <?php else: ?>
          <p class="text-gray-400">No music playing</p>
        <?php endif; ?>
      <?php else: ?>
        <p class="text-gray-400">No music playing</p>
      <?php endif; ?>
    </div>
    <?php if ($userProfile): ?>
      <a href="profile.php?id=<?php echo $_SESSION['user_id']; ?>" class="mt-4 px-4 py-2 bg-purple-600 rounded hover:bg-purple-700 text-center">
        Edit Profile
      </a>
    <?php else: ?>
      <a href="create_profile.php" class="mt-auto px-4 py-2 bg-purple-600 rounded hover:bg-purple-700 text-center">
        Create Profile
      </a>
    <?php endif; ?>
  </div>

  <!-- Main Content -->
  <div class="flex-1 flex flex-col">
    <!-- Wall Posts -->
    <div class="flex-1 overflow-y-auto p-4 posts-container">
      <h2 class="text-xl font-bold mb-4">Love4Free Wall</h2>
      <?php if (isset($error)): ?>
        <p class="text-red-500 mb-4"><?php echo $error; ?></p>
      <?php elseif (isset($success)): ?>
        <p class="text-green-500 mb-4"><?php echo $success; ?></p>
      <?php endif; ?>
      <?php if (!empty($_GET['term'])): ?>
        <a href="index.php" class="mb-4 inline-block px-4 py-2 bg-purple-600 rounded hover:bg-purple-700">Back to Wall</a>
      <?php endif; ?>
      <div id="posts">
        <?php foreach ($_SESSION['posts'] as $post): ?>
          <div class="p-3 mb-3 bg-gray-700 rounded-lg flex items-start">
            <?php if ($post['avatar']): ?>
              <a href="profile.php?id=<?php echo $post['profile_id']; ?>">
                <img src="<?php echo htmlspecialchars($post['avatar']); ?>" alt="Avatar" class="w-10 h-10 rounded-full mr-3">
              </a>
            <?php endif; ?>
            <div class="flex-1">
              <div class="flex justify-between items-center">
                <a href="profile.php?id=<?php echo $post['profile_id']; ?>" class="font-semibold text-purple-300 hover:underline">
                  <?php echo $post['user']; ?>
                </a>
                <span class="text-xs text-gray-400"><?php echo $post['time']; ?></span>
              </div>
              <p class="mt-1"><?php echo $post['content']; ?></p>
            </div>
          </div>
        <?php endforeach; ?>
      </div>
    </div>
    
    <!-- Post Form -->
    <?php if ($userProfile && empty($_GET['term'])): ?>
      <div class="p-4 border-t border-gray-700">
        <form method="POST" class="flex">
          <input type="text" name="content" placeholder="Share your love..." 
                 class="flex-1 p-2 bg-gray-700 rounded-l focus:outline-none">
          <button type="submit" class="px-4 py-2 bg-purple-600 rounded-r hover:bg-purple-700">
            Post
          </button>
        </form>
      </div>
    <?php endif; ?>
  </div>

  <!-- Right Sidebar - User Profiles -->
  <div class="w-80 p-4 bg-gray-800 overflow-y-auto">
    <h2 class="text-xl font-bold mb-4">Find Your Match</h2>
    <?php if ($userProfile): ?>
      <form method="GET" class="mb-4 flex">
        <input type="text" name="term" placeholder="Search..." 
               class="flex-1 p-2 bg-gray-700 rounded-l focus:outline-none">
        <button type="submit" class="px-4 py-2 bg-purple-600 rounded-r hover:bg-purple-700">
          Search
        </button>
      </form>
      <?php
      $query = "SELECT id, name, song, song_type, avatar FROM profiles";
      $params = [];
      if (!empty($_GET['term'])) {
          $query .= " WHERE (name LIKE ? OR bio LIKE ? OR hobbies LIKE ?)";
          $params[] = "%{$_GET['term']}%";
          $params[] = "%{$_GET['term']}%";
          $params[] = "%{$_GET['term']}%";
      }
      $stmt = $pdo->prepare($query);
      $stmt->execute($params);
      $profiles = $stmt->fetchAll(PDO::FETCH_ASSOC);
      if ($profiles) {
          foreach ($profiles as $profile) {
              echo '<a href="profile.php?id=' . $profile['id'] . '" class="block mb-3 p-3 bg-gray-700 rounded-lg hover:bg-gray-600 flex items-center">';
              if ($profile['avatar']) {
                  echo '<img src="' . htmlspecialchars($profile['avatar']) . '" alt="Avatar" class="w-10 h-10 rounded-full mr-3">';
              }
              echo '<div>';
              echo '<div class="font-semibold">' . htmlspecialchars($profile['name']) . '</div>';
              if ($profile['song']) {
                  echo '<div class="text-xs text-gray-300 mt-1">';
                  echo $profile['song_type'] === 'spotify' ? 'Listening on Spotify' : htmlspecialchars($profile['song']);
                  echo '</div>';
              }
              echo '</div>';
              echo '</a>';
          }
      } else {
          echo '<p class="text-gray-400">No profiles found.</p>';
      }
      ?>
    <?php else: ?>
      <p class="text-gray-400">Create a profile to search others!</p>
    <?php endif; ?>
  </div>

  <script>
    const postsContainer = document.getElementById('posts');
    if (postsContainer) {
      postsContainer.scrollTop = postsContainer.scrollHeight;
    }
  </script>
</body>
</html>