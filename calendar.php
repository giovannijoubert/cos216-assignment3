<?php
$pageName = "calendar";
include "header.php";
?>
       
      <div class="row">
         <div class="column left">
            <div  class="container">
               <div class="calendar light">
                  <div class="calendar_header">
                     <h1 class = "header_title">March 2019</h1>
                     <div id="cal_nav">
                        <a id="prev" ><i class="fas fa-arrow-left"></i>PREVIOUS</a>
                        <a id="today" >TODAY</a>
                        <a id="next" >NEXT <i class="fas fa-arrow-right"></i></a>
                     </div>
                  </div>
                  <div class="calendar_plan">
                     <div class="cl_plan">
                        <div class="cl_title">Release Date</div>
                        <div class="cl_copy">Movie Title</div>
                     </div>
                     <div class="spesific_date">
                        <label for="datepicker">Jump to spesific date: </label><input  type="date" id="datepicker" onchange="loadCalendar('datepicker')">
                     </div>
                  </div>
                  <p class="ce_title">The Month's Movies</p>
                  <div class="ce_loader">
                     <img alt="loader" src="img/ajax-loader-small.gif">
                  </div>
                  <div class="calendar_events">
                  </div>
               </div>
            </div>
             <button onclick="downloadCalendar()" id="DownloadCal" type="button">Download Calendar</button>
         </div>
         <div class="column right right-desc-loader">
            <img alt="loader" src="img/ajax-loader.gif">
         </div>
         <div class="column right right-desc">
            <h1 class="movie_title">Title</h1>
            <iframe class="youtube" src="https://www.youtube.com/embed/id61hcbdMZA" allowfullscreen></iframe>
            <span class="movie_release"></span>
            <p class="movie_desc"></p>
            <div class="single-poster-age-rating"></div>
         </div>
      </div>

<script src="js/cluedup_calendar.js"></script>
<script>loadCalendar();</script>

<?php
include "footer.php";
?>