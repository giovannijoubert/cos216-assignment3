<?php

require ("config.php");


// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);
// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
} 

if(!isset($_POST["FirstName"]) || !isset($_POST["LastName"]) || !isset($_POST["uEmail"]) || !isset($_POST["uPassword"]))
{
    echo "<div style='text-align:center;font-size:20px;'>One or more fields empty!</div>";
    header("refresh:3;url=index.php");
    die();
}

//Retrieve submitted data
$FirstName = $_POST["FirstName"];
$LastName = $_POST["LastName"];
$uEmail = $_POST["uEmail"];
$uPassword = $_POST["uPassword"];



//REVALIDATING user input SERVERSIDE

$emailRegEx = '/^(?!(?:(?:\\x22?\\x5C[\\x00-\\x7E]\\x22?)|(?:\\x22?[^\\x5C\\x22]\\x22?)){255,})(?!(?:(?:\\x22?\\x5C[\\x00-\\x7E]\\x22?)|(?:\\x22?[^\\x5C\\x22]\\x22?)){65,}@)(?:(?:[\\x21\\x23-\\x27\\x2A\\x2B\\x2D\\x2F-\\x39\\x3D\\x3F\\x5E-\\x7E]+)|(?:\\x22(?:[\\x01-\\x08\\x0B\\x0C\\x0E-\\x1F\\x21\\x23-\\x5B\\x5D-\\x7F]|(?:\\x5C[\\x00-\\x7F]))*\\x22))(?:\\.(?:(?:[\\x21\\x23-\\x27\\x2A\\x2B\\x2D\\x2F-\\x39\\x3D\\x3F\\x5E-\\x7E]+)|(?:\\x22(?:[\\x01-\\x08\\x0B\\x0C\\x0E-\\x1F\\x21\\x23-\\x5B\\x5D-\\x7F]|(?:\\x5C[\\x00-\\x7F]))*\\x22)))*@(?:(?:(?!.*[^.]{64,})(?:(?:(?:xn--)?[a-z0-9]+(?:-+[a-z0-9]+)*\\.){1,126}){1,}(?:(?:[a-z][a-z0-9]*)|(?:(?:xn--)[a-z0-9]+))(?:-+[a-z0-9]+)*)|(?:\\[(?:(?:IPv6:(?:(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){7})|(?:(?!(?:.*[a-f0-9][:\\]]){7,})(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,5})?::(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,5})?)))|(?:(?:IPv6:(?:(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){5}:)|(?:(?!(?:.*[a-f0-9]:){5,})(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,3})?::(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,3}:)?)))?(?:(?:25[0-5])|(?:2[0-4][0-9])|(?:1[0-9]{2})|(?:[1-9]?[0-9]))(?:\\.(?:(?:25[0-5])|(?:2[0-4][0-9])|(?:1[0-9]{2})|(?:[1-9]?[0-9]))){3}))\\]))$/iD';

if(!preg_match($emailRegEx, $uEmail)){
    echo "<div style='text-align:center;font-size:20px;'>Invalid Email!</div>";
    header("refresh:3;url=index.php");
    die();
}

$passwordRegEx = "/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{9,})/";

if(!preg_match($passwordRegEx, $uPassword)){
    echo "<div style='text-align:center;font-size:20px;'>Password needs to contain: Uppercase, Lowercase, Special as well as Numeric characters and be at least 8 characters long.</div>";
    header("refresh:3;url=index.php");
    die();
}

//Hasing the password, generating dynamic salt and storing it
$uSalt = generateSalt();

$options = array(
    'salt' => $uSalt
);
//PASSWORD_DEFAULT ensures the latest, most secure algorithm is used (currently PASSWORD_BCRYPT)
$password_hash = password_hash($uPassword, PASSWORD_DEFAULT, $options);

//Generate APIKey
$uAPIKey = bin2hex(openssl_random_pseudo_bytes(32));

//Checking for Duplicate user
$sql = "SELECT * FROM Users WHERE uEmail='$uEmail'";
$result = $conn->query($sql); 
    
if ($result->num_rows > 0)
{
    echo "<div style='text-align:center;font-size:20px;'>Email already exists in database! Redirecting back to sign-up...</div>";
    header("refresh:3;url=signup.php");
} else {

//Insert User into DB
$sql = "INSERT INTO Users (FirstName, LastName, uEmail, uPassword, uSalt, uAPIKey)
VALUES ('$FirstName', '$LastName', '$uEmail', '$password_hash', '$uSalt', '$uAPIKey')";

if ($conn->query($sql) === TRUE) {
    echo "<div style='text-align:center;font-size:20px;'>Welcome to CluedUP! <br/> Your new API key: $uAPIKey <br/> Redirecting to Home Page in 10 seconds...</div>";
    header("refresh:10;url=index.php");
die();
    
} else {
    echo "Error: " . $sql . "<br>" . $conn->error;
}
}

$conn->close();




function generateSalt() {
     $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/\\][{}\;:?.>,<!@#$%^&*()-_=+|';
     $randStringLen = 64;

     $randString = "";
     for ($i = 0; $i < $randStringLen; $i++) {
         $randString .= $characters[mt_rand(0, strlen($characters) - 1)];
     }

     return $randString;
}


?>