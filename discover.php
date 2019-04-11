<?php
$pageName = "discover";
include "header.php";
?>

      <div class="body-elements">
         <div class="filter-container">
            <input type="text" class="search-bar" id="search-bar" placeholder="  Looking for a particular movie?">
            <a ><i onclick="searchDiscover()" class="fa fa-search search-icon"></i></a>
            <div class="filter-rating">
               <div class="rate" >
                  <input onclick="filterRating()" type="radio" id="star5" name="rate" value="5" />
                  <label for="star5" title="text">5 stars</label>
                  <input onclick="filterRating()" type="radio" id="star4" name="rate" value="4" />
                  <label for="star4" title="text">4 stars</label>
                  <input onclick="filterRating()" type="radio" id="star3" name="rate" value="3" />
                  <label for="star3" title="text">3 stars</label>
                  <input onclick="filterRating()" type="radio" id="star2" name="rate" value="2" />
                  <label for="star2" title="text">2 stars</label>
                  <input onclick="filterRating()" type="radio" id="star1" name="rate" value="1" />
                  <label for="star1" title="text">1 star</label>
               </div>
            </div>
            <span class="filter-genre">
               <select id="genrefilter" onchange="filterGenre()">
                  <option selected disabled>Genre</option>
                  <option value="28">Action</option>
                  <option value="12">Adventure</option>
                  <option value="16">Animation</option>
                  <option value="35">Comedy</option>
                  <option value="80">Crime</option>
                  <option value="99">Documentary</option>
                  <option value="18">Drama</option>
                  <option value="10751">Family</option>
                  <option value="14">Fantasy</option>
                  <option value="36">History</option>
                  <option value="27">Horror</option>
                  <option value="10402">Music</option>
                  <option value="9648">Mystery</option>
                  <option value="10749">Romance</option>
                  <option value="878">Science Fiction</option>
                  <option value="53">Thriller</option>
                  <option value="10752">War</option>
                  <option value="37">Western</option>
               </select>
            </span>
            <p onclick="clearFilters()" id="clearfilters">Clear filters</p>
         </div>
      </div>
      <div class="posters-holder">
      </div>
      <!--body elements-->

<script>loadDiscover();</script>

<?php
include "footer.php";
?>