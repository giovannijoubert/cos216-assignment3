<?php
require_once("config.php"); 



echo "<!DOCTYPE html>
<html lang='en'>
   <head>
      <meta charset='UTF-8'>
      <title>" . ucfirst($pageName) . " | CluedUP - The Premiere Movie Database</title>
      <meta name='author' content='Giovanni Joubert'>
      <meta name='description' content='The Premiere Movie Database'>
      <link rel='stylesheet' href='css/main.css' type='text/css'>";
      if($pageName == "calendar") echo "<link rel='stylesheet' href='css/calendar.css' type='text/css'>";
      if($pageName == "discover" || $pageName == "top-rated" || $pageName == "latest") echo "<link rel='stylesheet' href='css/discover.css' type='text/css'>";
      if($pageName == "featured") echo "<link rel='stylesheet' href='css/featured.css' type='text/css'>";
      if($pageName == "top-rated") echo "<link rel='stylesheet' href='css/top-rated.css' type='text/css'>";
      if($pageName == "latest") echo "<link rel='stylesheet' href='css/latest.css' type='text/css'>";
echo  "<link rel='icon' href='img/favico.png' type='image/png'>
      <link rel='stylesheet' href='https://use.fontawesome.com/releases/v5.7.1/css/all.css' integrity='sha384-fnmOCqbTlWIlj8LyTjo7mOUStjsKC4pOpQbqyi7RrhN7udi9RwhKkMHpvLbHG9Sr' crossorigin='anonymous'>
      <meta content='width=device-width, initial-scale=1' name='viewport' />
      <script src='js/cluedup.js'></script>
      <script src='js/cluedup_login.js'></script>
      <script src='https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js'></script>
   </head>
   <body>
  <header>
         <nav>
            <span><img alt='CluedUP Logo' class='topLogo' src='img/mainlogo.svg'></span>
            <ul class='topNav'> ";
            
               if($loggedIn){
                   echo "<li id='logoutBtn' ><a href=''><i class='fa fa-sign-out-alt'></i>Logout</a></li>
                         <li id='logoutBtn' ><a> Hi " . $userName . "! </a></li>";
               } else {
                   echo "<li id='loginBtn' ><a href=''><i class='fa fa-sign-in-alt'></i>Login</a></li>
                        <li id='registerBtn' ><a href='signup.php'><i class='fa fa-user'></i>Register</a></li>";
               }
                
            
               echo "<li><a "; if($pageName == "welcome") echo " class='activeNav' "; echo "href='index.php'><i class='fa fa-home'></i>Home</a></li>
               <li><a "; if($pageName == "discover") echo " class='activeNav' "; echo "href='discover.php'><i class='fa fa-search'></i>Discover</a></li>
               <li><a "; if($pageName == "featured") echo " class='activeNav' "; echo " href='featured.php'><i class='fa fa-star' ></i>Featured</a></li>
               <li><a "; if($pageName == "top-rated") echo " class='activeNav' "; echo " href='top-rated.php'><i class='far fa-thumbs-up' ></i>Top Rated</a></li>
               <li><a "; if($pageName == "latest") echo " class='activeNav' "; echo " href='latest.php'><i class='fas fa-bullhorn' ></i>Latest</a></li>
               <li><a "; if($pageName == "calendar") echo " class='activeNav' "; echo " href='calendar.php'><i class='fa fa-calendar-alt' ></i>Calendar</a></li>
            </ul>
         </nav>   
         <div class='welcome-msg'>
            <h1>" . ucfirst($pageName) . "</h1>
            <h3>The Premiere Movie Database</h3>
         </div>";
        if($pageName != "featured"){
        echo " <svg class='custom-header-shape' xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100' preserveAspectRatio='none'>
            <polygon fill='white' points='0,100 100,0 100,100'/>
         </svg>";
        }
             
      echo "</header>";


?>