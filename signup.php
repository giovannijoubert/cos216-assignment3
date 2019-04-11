<?php
$pageName = "signup";
include "header.php";
?>

<form id="signup" action="validate-signup.php" onsubmit="return validateSignUp()" method="post">
  <div class="sign_container">
    <h1>Register</h1>
    <p>Please fill in the form below to create a CluedUP account.</p>
    <hr>

 <label for="FirstName"><b>First Name</b></label>
    <input type="text" id="FirstName" placeholder="Enter First Name" name="FirstName" required>
      
       <label for="LastName"><b>Last Name</b></label>
    <input type="text" id="LastName" placeholder="Enter Last Name" name="LastName" required>
      
    <label for="uEmail"><b>Email</b></label>
    <input type="text" id="uEmail" placeholder="Enter Email" name="uEmail" required>

    <label for="uPassword"><b>Password</b></label>
    <input type="password" id="uPassword" placeholder="Enter Password" name="uPassword" required>

    <label for="uPassword2"><b>Repeat Password</b></label>
    <input type="password" id="uPassword2" placeholder="Repeat Password" name="uPassword2" required>
    <hr>

    <button type="submit" class="registerbtn">Register</button>
  </div>

  <div class="sign_container signin">
    <p>Already have an account? <a href="#">Sign in</a>.</p>
  </div>
</form>
    
     
<script></script>

<?php
include "footer.php";
?>