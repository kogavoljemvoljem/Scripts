<?php
if (file_exists('install.lock')) {
    die("Installation already completed. Delete 'install.lock' to reinstall.");
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $host = $_POST['host'] ?? '';
    $dbname = $_POST['dbname'] ?? '';
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // Test database connection
    try {
        $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Create profiles table with enhanced schema
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS profiles (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(50) NOT NULL,
                bio TEXT,
                song VARCHAR(255),
                song_type VARCHAR(20),
                personality VARCHAR(50),
                job VARCHAR(50),
                hobbies TEXT,
                love TEXT,
                travel VARCHAR(50),
                video VARCHAR(255),
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ");

        // Update db.php with credentials
        $dbContent = <<<PHP
<?php
\$host = "$host";
\$dbname = "$dbname";
\$username = "$username";
\$password = "$password";

try {
    \$pdo = new PDO("mysql:host=\$host;dbname=\$dbname", \$username, \$password);
    \$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException \$e) {
    die("Connection failed: " . \$e->getMessage());
}
?>
PHP;
        file_put_contents('db.php', $dbContent);

        // Create install.lock
        file_put_contents('install.lock', 'Installation completed on ' . date('Y-m-d H:i:s'));

        // Delete this script
        unlink(__FILE__);

        echo "<!DOCTYPE html>
        <html lang='en'>
        <head>
            <meta charset='UTF-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
            <title>Installation Successful</title>
            <script src='https://cdn.tailwindcss.com'></script>
        </head>
        <body class='bg-gray-900 text-white flex items-center justify-center min-h-screen'>
            <div class='p-6 bg-gray-800 rounded max-w-md w-full text-center'>
                <h1 class='text-2xl font-bold mb-4 text-green-500'>Installation Successful!</h1>
                <p class='mb-4'>Love4Free has been successfully installed.</p>
                <a href='index.php' class='px-4 py-2 bg-purple-600 rounded hover:bg-purple-700 inline-block'>
                    Go to Love4Free
                </a>
            </div>
        </body>
        </html>";
        exit;
    } catch (PDOException $e) {
        $error = "Database Error: " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Love4Free - Install</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white flex items-center justify-center min-h-screen">
  <div class="p-6 bg-gray-800 rounded max-w-md w-full">
    <h1 class="text-2xl font-bold mb-4">Install Love4Free</h1>
    <?php if (isset($error)): ?>
      <p class="text-red-500 mb-4"><?php echo $error; ?></p>
    <?php endif; ?>
    <p class="mb-4">Enter your MySQL database details:</p>
    <form method="POST">
      <label class="block mb-2">Host (e.g., sql123.epizy.com):</label>
      <input type="text" name="host" class="w-full p-2 bg-gray-700 rounded mb-4" required>
      
      <label class="block mb-2">Database Name:</label>
      <input type="text" name="dbname" class="w-full p-2 bg-gray-700 rounded mb-4" required>
      
      <label class="block mb-2">Username:</label>
      <input type="text" name="username" class="w-full p-2 bg-gray-700 rounded mb-4" required>
      
      <label class="block mb-2">Password:</label>
      <input type="password" name="password" class="w-full p-2 bg-gray-700 rounded mb-4" required>
      
      <button type="submit" class="px-4 py-2 bg-purple-600 rounded hover:bg-purple-700 w-full">
        Install
      </button>
    </form>
    <p class="mt-4 text-gray-400 text-sm">
      Note: You can find these details in your hosting control panel under MySQL Databases.
    </p>
  </div>
</body>
</html>