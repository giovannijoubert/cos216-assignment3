<?php
$pageName = "latest";
include "header.php";
?>

      <div id="loader" >
         <img alt="loader" src="img/ajax-loader.gif">
      </div>
      <div class="posters-holder">
      </div>
      <!--body elements-->
<script>latestLoadItems();</script>
<?php
include "footer.php";
?>