function validateSignUp(){
    
    //Clear all previous responses
    $("*").removeClass("invalid_response");
    $(".form-response").fadeOut(300);
    $(".form-response").delay(300).html("");

    //Get form data from DOM
    var FirstName = document.getElementById("FirstName");
    var LastName = document.getElementById("LastName");
    var uEmail = document.getElementById("uEmail");
    var uPassword = document.getElementById("uPassword");
    var uPassword2 = document.getElementById("uPassword2");
    
    //validate email
    if(!validateEmail(uEmail.value)){
        $("#uEmail").addClass("invalid_response");
        $("#uEmail").before("<span class='form-response'>Invalid email address.</span>");
        $(".form-response").fadeIn();
        return false;
    }
    
    //Check if password confirmation matches
    if(uPassword.value != uPassword2.value){
        $("#uPassword").addClass("invalid_response");
        $("#uPassword2").addClass("invalid_response");
        $("#uPassword").before("<span class='form-response'>Passwords don't match.</span>");
        $(".form-response").fadeIn();
        return false;
    } 
    
    //validate password
    if(!validatePassword(uPassword.value)){
         $("#uPassword").addClass("invalid_response");
         $("#uPassword").before("<span class='form-response'>Password needs to contain: Uppercase, Lowercase, Special as well as Numeric characters and be at least 8 characters long.</span>");
         $(".form-response").fadeIn();
         return false;
    }
  
    //No validation errors baby!
    return true;
}

function validateEmail(email){
    var emailRegEx = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    
    if(emailRegEx.test(email)){
         return true;
    } else {
         return false;
    }
    
}

function validatePassword(pass){
    //(?=.*[a-z]) contain at least one lowercase
    //(?=.*[A-Z]) contain at least one uppercase
    //(?=.*[0-9]) contain at least one numeric
    //(?=.[!@#\$%\^&]) contain one or more of these special characters
    //(?=.{9,}) 9 or more characters (SPEC STATES MORE THAN 8, THUS 9+)
    var passwordRegEx = new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{9,})");
    
    if(passwordRegEx.test(pass)){
         return true;
    } else {
         return false;
    }
}