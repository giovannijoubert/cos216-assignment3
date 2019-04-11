function loadSplashPosters()
{

	var movie_count = 12;


	for (var j = 0; j < movie_count; j++)
	{
		var node = document.createElement("img");

		node.style.height = "270px";
		node.style.width = "180px";
		node.style.background = "url(img/ajax-loader-small.gif)";
		node.style.backgroundRepeat = "no-repeat";
		node.style.backgroundPosition = "center";
		node.style.backgroundSize = "150px";
		node.style.border = "solid 2px #00C6A7";

		node.classList.add("single-splash-poster");
		document.getElementsByClassName("hero-posters")[0].appendChild(node);
	}


	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function ()
	{
		if (this.readyState == 4 && this.status == 200)
		{
			var JSONObj = JSON.parse(this.responseText);

			var i = 0;

			function ReplaceLoaders()
			{
				setTimeout(function ()
				{
					$(".single-splash-poster").eq(i).hide();
					$(".single-splash-poster").eq(i).css("width", "unset");
					$(".single-splash-poster").eq(i).css("height", "unset");
					$(".single-splash-poster").eq(i).css("border", "none");
					$(".single-splash-poster").eq(i).attr("src", "https://image.tmdb.org/t/p/w300/" + JSONObj.results[i].poster_path).stop(true, true).hide().fadeIn(300);

					i++;
					if (i < $(".single-splash-poster").length)
					{
						ReplaceLoaders();
					}
				}, 50);
			}

			ReplaceLoaders();


		}
	};
	xhttp.open("GET", "https://api.themoviedb.org/3/trending/movie/day?api_key=3f51c3329a20300b741b815efe1b5daa", true);
	xhttp.send();
}


function discoverCreateItems(count)
{

	document.getElementsByClassName("posters-holder")[0].innerHTML = "";

	for (var j = 0; j < count; j++)
	{
		var single_poster_holder = document.createElement("div");
		single_poster_holder.classList.add("single-poster-holder");
		var poster = document.createElement("img");
		poster.classList.add("single-poster-layer_bottom");
		poster.style.background = "url(img/ajax-loader-small.gif)";
		poster.style.width = "335px";
		poster.style.backgroundRepeat = "no-repeat";
		poster.style.backgroundSize = "100px";
		poster.style.backgroundPosition = "center";
		poster.style.height = "502px";
		single_poster_holder.appendChild(poster);
		var descriptionLayer = document.createElement("div");
		descriptionLayer.classList.add("single-poster-layer_top");
		single_poster_holder.appendChild(descriptionLayer);
		var title = document.createElement("h1");
		var releaseYear = document.createElement("h2");
		var imdbRating = document.createElement("span");
		imdbRating.classList.add("imdb_rating");
		var cluedupRating = document.createElement("span");
		cluedupRating.classList.add("CluedUP_rating");
		var desc = document.createElement("p");
		var ageRating = document.createElement("div");
		ageRating.classList.add("single-poster-age-rating");

		descriptionLayer.appendChild(title);

		descriptionLayer.appendChild(releaseYear);

		descriptionLayer.appendChild(imdbRating);

		descriptionLayer.appendChild(cluedupRating);

		descriptionLayer.appendChild(desc);
		descriptionLayer.appendChild(ageRating);

		document.getElementsByClassName("posters-holder")[0].appendChild(single_poster_holder);
	}

}



function searchDiscover()
{

	var qry = document.getElementById("search-bar").value;

	if (qry == "")
	{
		alert("Please enter a search query first.");
		return;
	}

	$.ajax(
	{
		url: "https://api.themoviedb.org/3/search/movie?api_key=3f51c3329a20300b741b815efe1b5daa&language=en-US&query=" + qry + "&page=1&include_adult=false",

		data:
		{
			format: "json"
		},

		success: function (response)
		{


			var count = Math.min(9, response.results.length);

			discoverCreateItems(count);

			for (i = 0; i < count; i++)
			{

				if (response.results[i].poster_path != null)
				{
					document.getElementsByClassName("single-poster-holder")[i].getElementsByTagName("img")[0].src = "https://image.tmdb.org/t/p/w500/" + response.results[i].poster_path;






					var att = document.createAttribute("data-movie-genre");
					att.value = response.results[i].genre_ids;
					document.getElementsByClassName("single-poster-holder")[i].setAttributeNode(att);

					document.getElementsByClassName("single-poster-holder")[i].getElementsByTagName("img")[0].alt = response.results[i].title;
					document.getElementsByClassName("single-poster-layer_top")[i].getElementsByTagName("h1")[0].innerHTML =
						response.results[i].title;
					document.getElementsByClassName("single-poster-layer_top")[i].getElementsByTagName("h2")[0].innerHTML =
						response.results[i].release_date;
					document.getElementsByClassName("single-poster-layer_top")[i].getElementsByClassName("imdb_rating")[0].innerHTML =
						"★" + response.results[i].vote_average;
					document.getElementsByClassName("single-poster-layer_top")[i].getElementsByClassName("CluedUP_rating")[0].innerHTML =
						" " + Math.floor((Math.random() * 100) + 1) + "%";
					document.getElementsByClassName("single-poster-layer_top")[i].getElementsByTagName("p")[0].innerHTML =
						(response.results[i].overview).substring(0, 200);
					if ((response.results[i].overview).length > 200)
					{
						document.getElementsByClassName("single-poster-layer_top")[i].getElementsByTagName("p")[0].innerHTML += "...";
					}


					$.ajax(
					{

						url: "https://api.themoviedb.org/3/movie/" + response.results[i].id + "?api_key=3f51c3329a20300b741b815efe1b5daa&append_to_response=release_dates",


						data:
						{
							format: "json"
						},


						indexValue: i,
						success: function (response, indexValue)
						{




							for (j = 0; j < (response.release_dates.results).length; j++)
							{

								if (response.release_dates.results[j].iso_3166_1 == "US")
								{
									document.getElementsByClassName("single-poster-layer_top")[this.indexValue].getElementsByClassName("single-poster-age-rating")[0].innerHTML =
										response.release_dates.results[j].release_dates[0].certification;
									break;
								}
							}

							if (document.getElementsByClassName("single-poster-layer_top")[this.indexValue].getElementsByClassName("single-poster-age-rating")[0].innerHTML == "")
							{
								document.getElementsByClassName("single-poster-layer_top")[this.indexValue].getElementsByClassName("single-poster-age-rating")[0].style.display = "none";
							}


						}
					});

				}
				else
				{
					document.getElementsByClassName("single-poster-holder")[i].style.display = "none";
				}

			}

			clearFilters(true);




		}
	});







}


function ShrinkAnim(elemNo)
{
	var elem = document.getElementsByClassName("single-poster-holder")[elemNo].getElementsByTagName("img")[0];
	var id = setInterval(frame, 5);
	var scale = 100;

	function frame()
	{
		if (scale == 0)
		{
			$(".single-poster-holder").eq(elemNo).fadeOut(1);
			clearInterval(id);
		}
		else
		{
			scale--;
			elem.style.height = 490 * (scale / 100) + "px";
			elem.style.width = 335 * (scale / 100) + "px";
		}
	}
}

function unShrinkAnim(elemNo)
{
	var elem = document.getElementsByClassName("single-poster-holder")[elemNo].getElementsByTagName("img")[0];
	$(".single-poster-holder").eq(elemNo).fadeIn(1);

	var id = setInterval(frame, 5);
	var scale = 0;

	function frame()
	{
		if (scale == 100)
		{
			clearInterval(id);
		}
		else
		{
			scale++;
			elem.style.height = 490 * (scale / 100) + "px";
			elem.style.width = 335 * (scale / 100) + "px";
		}
	}
}


var ratingActive = false;
var genreActive = false;

function clearFilters(s)
{
	document.getElementById("genrefilter").value = "Genre";

	var elems = document.getElementsByClassName("single-poster-holder");

	document.getElementById("star1").checked = false;
	document.getElementById("star2").checked = false;
	document.getElementById("star3").checked = false;
	document.getElementById("star4").checked = false;
	document.getElementById("star5").checked = false;


	for (i = 0; i < elems.length; i++)
	{
		if (s)
		{}
		else if ($(".single-poster-holder img").eq(i).attr("src"))
		{
			unShrinkAnim(i);
		}
	}
	ratingActive = false;
	genreActive = false;
}




function filterRatingGenre()
{

	var gNo = document.getElementById("genrefilter").value;
	var r;
	if (document.getElementById("star1").checked)
	{
		r = 2;
	}
	if (document.getElementById("star2").checked)
	{
		r = 4;
	}
	if (document.getElementById("star3").checked)
	{
		r = 6;
	}
	if (document.getElementById("star4").checked)
	{
		r = 8;
	}
	if (document.getElementById("star5").checked)
	{
		r = 9;
	}
	var elems = document.getElementsByClassName("single-poster-holder");

	if (r)
	{

		for (i = 0; i < elems.length; i++)
		{
			ShrinkAnim(i);
		}







		setTimeout(function ()
		{
			for (i = 0; i < elems.length; i++)
			{




				if ((elems[i].getElementsByClassName("imdb_rating")[0].innerHTML).substring(1, (elems[i].getElementsByClassName("imdb_rating")[0].innerHTML).length) < r ||
					elems[i].getAttribute("data-movie-genre").split(',').indexOf(gNo) <= -1
				)
				{}
				else
				{
					unShrinkAnim(i);
				}


			}





		}, 600);


		genreActive = true;
		ratingActive = true;


	}

}



function filterRating()
{
	var r;
	if (document.getElementById("star1").checked)
	{
		r = 2;
	}
	if (document.getElementById("star2").checked)
	{
		r = 4;
	}
	if (document.getElementById("star3").checked)
	{
		r = 6;
	}
	if (document.getElementById("star4").checked)
	{
		r = 8;
	}
	if (document.getElementById("star5").checked)
	{
		r = 9;
	}

	if (r)
	{

		var elems = document.getElementsByClassName("single-poster-holder");

		if (genreActive)
		{
			filterRatingGenre();
			return;
		}



		for (i = 0; i < elems.length; i++)
		{
			ShrinkAnim(i);
		}

		setTimeout(function ()
		{

			for (i = 0; i < elems.length; i++)
			{
				if ((elems[i].getElementsByClassName("imdb_rating")[0].innerHTML).substring(1, (elems[i].getElementsByClassName("imdb_rating")[0].innerHTML).length) > r)
				{
					unShrinkAnim(i);
				}

			}
		}, 600);





		ratingActive = true;



	}



}




function filterGenre()
{


	var gNo = document.getElementById("genrefilter").value;


	var elems = document.getElementsByClassName("single-poster-holder");

	if (ratingActive)
	{
		filterRatingGenre();
		return;
	}

	for (i = 0; i < elems.length; i++)
	{
		ShrinkAnim(i);
	}

	setTimeout(function ()
	{


		for (i = 0; i < elems.length; i++)
		{



			if (elems[i].getAttribute("data-movie-genre").split(',').indexOf(gNo) > -1)
			{
				unShrinkAnim(i);
			}


		}
	}, 600);



	genreActive = true;


}

function loadDiscover()
{

	var itemCount = 12;

	discoverCreateItems(itemCount);



	$.ajax(
	{
		url: "https://api.themoviedb.org/3/discover/movie?api_key=3f51c3329a20300b741b815efe1b5daa&language=en-US®ion=US&sort_by=popularity.desc&certification_country=US&include_adult=false&include_video=false&page=1&append_to_response=releases",

		data:
		{
			format: "json"
		},


		success: function (response)
		{


			for (i = 0; i < itemCount; i++)
			{
				document.getElementsByClassName("single-poster-holder")[i].getElementsByTagName("img")[0].src = "https://image.tmdb.org/t/p/w500/" + response.results[i].poster_path;

				var att = document.createAttribute("data-movie-genre");
				att.value = response.results[i].genre_ids;
				document.getElementsByClassName("single-poster-holder")[i].setAttributeNode(att);

				document.getElementsByClassName("single-poster-holder")[i].getElementsByTagName("img")[0].alt = response.results[i].title;
				document.getElementsByClassName("single-poster-layer_top")[i].getElementsByTagName("h1")[0].innerHTML =
					response.results[i].title;
				document.getElementsByClassName("single-poster-layer_top")[i].getElementsByTagName("h2")[0].innerHTML =
					response.results[i].release_date;
				document.getElementsByClassName("single-poster-layer_top")[i].getElementsByClassName("imdb_rating")[0].innerHTML =
					"★" + response.results[i].vote_average;
				document.getElementsByClassName("single-poster-layer_top")[i].getElementsByClassName("CluedUP_rating")[0].innerHTML =
					" " + Math.floor((Math.random() * 100) + 1) + "%";
				document.getElementsByClassName("single-poster-layer_top")[i].getElementsByTagName("p")[0].innerHTML =
					(response.results[i].overview).substring(0, 200);
				if ((response.results[i].overview).length > 200)
				{
					document.getElementsByClassName("single-poster-layer_top")[i].getElementsByTagName("p")[0].innerHTML += "...";
				}


				$.ajax(
				{

					url: "https://api.themoviedb.org/3/movie/" + response.results[i].id + "?api_key=3f51c3329a20300b741b815efe1b5daa&append_to_response=release_dates",


					data:
					{
						format: "json"
					},


					indexValue: i,
					success: function (response, indexValue)
					{




						for (j = 0; j < (response.release_dates.results).length; j++)
						{

							if (response.release_dates.results[j].iso_3166_1 == "US")
							{
								document.getElementsByClassName("single-poster-layer_top")[this.indexValue].getElementsByClassName("single-poster-age-rating")[0].innerHTML =
									response.release_dates.results[j].release_dates[0].certification;
								break;
							}
						}

						if (document.getElementsByClassName("single-poster-layer_top")[this.indexValue].getElementsByClassName("single-poster-age-rating")[0].innerHTML == "")
						{
							document.getElementsByClassName("single-poster-layer_top")[this.indexValue].getElementsByClassName("single-poster-age-rating")[0].style.display = "none";
						}


					}
				});

			}


		}
	});
}


function loadTopRatedPosters()
{


	$.ajax(
	{
		url: "https://www.myapifilms.com/imdb/top?start=1&end=12&token=6ebc4543-c03d-43f6-85c8-baa2e737de05&format=json&data=0",


		jsonp: "callback",


		dataType: "jsonp",


		data:
		{
			format: "json"
		},


		success: function (response)
		{


			var singlePoster = document.getElementsByClassName("single-poster-holder");
			for (var i = 0; i < 12; i++)
			{

				var id = response.data.movies[i].idIMDB;


				singlePoster[i].getElementsByTagName("h1")[0].innerHTML = response.data.movies[i].title;

				singlePoster[i].getElementsByClassName("imdb_rating")[0].innerHTML = "★ " + response.data.movies[i].rating + "/10";


				$.ajax(
				{
					url: "https://api.themoviedb.org/3/movie/" + id + "?api_key=3f51c3329a20300b741b815efe1b5daa&language=en-US",
					data:
					{
						format: "json"

					},
					indexValue: i,
					success: function (response, indexValue)
					{


						singlePoster[this.indexValue].getElementsByTagName("p")[0].innerHTML = "$" + (response.revenue / 1000000).toFixed(2) + "M";

					}
				});


				$.ajax(
				{
					url: "http://www.omdbapi.com/?i=" + id + "&apikey=d3422035",
					data:
					{
						format: "json"
					},
					indexValue: i,
					success: function (response, indexValue)
					{

						singlePoster[this.indexValue].getElementsByTagName("img")[0].src = response.Poster;
						singlePoster[this.indexValue].getElementsByTagName("h2")[0].innerHTML = response.Genre;

						if (this.indexValue == 11)
						{

							$("#loader").fadeOut("slow", function ()
							{
								$(".posters-holder").fadeIn("slow");

							});

						}

					}
				});


			}


		}
	});


}

function latestLoadItems()
{
	latestCreateItems(6);



	$.ajax(
	{
		url: "   https://www.myapifilms.com/imdb/inTheaters?token=6ebc4543-c03d-43f6-85c8-baa2e737de05&format=json&language=en-us",


		jsonp: "callback",


		dataType: "jsonp",


		data:
		{
			format: "json"
		},




		success: function (response)
		{


			for (i = 0; i < 6; i++)
			{

				document.getElementsByClassName("single-poster-holder")[i].getElementsByTagName("h1")[0].innerHTML =
					response.data.inTheaters[1].movies[i].title;
				document.getElementsByClassName("single-poster-holder")[i].getElementsByTagName("h2")[0].innerHTML =
					"<i class='fa fa-flag' ></i>" + response.data.inTheaters[1].movies[i].countries;


				var rDate = response.data.inTheaters[1].movies[i].releaseDate;

				document.getElementsByClassName("single-poster-holder")[i].getElementsByTagName("h2")[1].innerHTML =
					"<i class='fa fa-calendar-alt' ></i>" + rDate.substring(0, 4) + "-" + rDate.substring(4, 6) + "-" + rDate.substring(6, 8);


				document.getElementsByClassName("single-poster-holder")[i].getElementsByTagName("h2")[2].innerHTML =
					"<i class='fa fa-clock' ></i>" + response.data.inTheaters[1].movies[i].runtime;

				document.getElementsByClassName("popup")[i].getElementsByTagName("h1")[0].innerHTML =
					response.data.inTheaters[1].movies[i].title;

				var id = response.data.inTheaters[1].movies[i].idIMDB;



				$.ajax(
				{
					url: "https://api.themoviedb.org/3/movie/" + id + "?api_key=3f51c3329a20300b741b815efe1b5daa&language=en-US&append_to_response=videos",
					data:
					{
						format: "json"

					},
					indexValue: i,
					success: function (response, indexValue)
					{

						document.getElementsByClassName("single-poster-holder")[this.indexValue].getElementsByTagName("img")[0].src = "https://image.tmdb.org/t/p/w300/" + response.poster_path;



						document.getElementsByClassName("youtube-popup")[this.indexValue].getElementsByTagName("embed")[0].src =
							"http://youtube.com/embed/" + response.videos.results[0].key;

						if (this.indexValue == 5)
						{


							setTimeout(function ()
							{

								$("#loader").fadeOut("slow", function ()
								{
									$(".posters-holder").fadeIn("slow");
								});

							}, 1000);
						}



					}
				});









			}
		}
	});

}


function latestCreateItems(count)
{

	document.getElementsByClassName("posters-holder")[0].innerHTML = "";

	for (var j = 0; j < count; j++)
	{
		var single_poster_holder = document.createElement("div");
		single_poster_holder.classList.add("single-poster-holder");
		var poster = document.createElement("img");
		poster.classList.add("single-poster-layer_bottom");
		single_poster_holder.appendChild(poster);
		var descriptionLayer = document.createElement("div");
		descriptionLayer.classList.add("single-poster-layer_top");
		single_poster_holder.appendChild(descriptionLayer);
		var title = document.createElement("h1");
		var country = document.createElement("h2");
		var releaseDate = document.createElement("h2");
		var runtime = document.createElement("h2");
		country.classList.add("country");
		releaseDate.classList.add("releaseDate");
		runtime.classList.add("runtime");

		var trailerbtn = document.createElement("div");
		trailerbtn.classList.add("trailer-button");
		trailerbtn.innerHTML = "<i class='fa fa-play' ></i><a href='#popup" + (j + 1) + "'> Trailer</a>";

		descriptionLayer.appendChild(title);

		descriptionLayer.appendChild(country);

		descriptionLayer.appendChild(releaseDate);

		descriptionLayer.appendChild(runtime);

		descriptionLayer.appendChild(trailerbtn);

		document.getElementsByClassName("posters-holder")[0].appendChild(single_poster_holder);


	}

	for (var k = 0; k < count; k++)
	{
		var popup = document.createElement("div");
		popup.classList.add("overlay");
		popup.id = "popup" + (k + 1);
		var popupInner = document.createElement("div");
		popupInner.classList.add("popup");
		var popupTitle = document.createElement("h1");
		var closeLink = document.createElement("a");
		closeLink.classList.add("close");
		closeLink.href = ("#");
		closeLink.innerHTML = "&times;";
		var content = document.createElement("div");
		content.classList.add("content");
		var ytpopup = document.createElement("div");
		ytpopup.classList.add("youtube-popup");
		var vid = document.createElement("embed");
		vid.width = "420px";
		vid.height = "315px";

		ytpopup.appendChild(vid);
		content.appendChild(ytpopup);
		popupInner.appendChild(popupTitle);
		popupInner.appendChild(closeLink);
		popupInner.appendChild(content);
		popup.appendChild(popupInner);

		document.getElementsByClassName("posters-holder")[0].appendChild(popup);
	}

}

function loadFeatured()
{

	var count = 8;
	createFeatured(count);

	$.ajax(
	{
		url: "https://api.themoviedb.org/3/discover/movie?api_key=3f51c3329a20300b741b815efe1b5daa&language=en-US&region=US&sort_by=popularity.desc&certification_country=US&include_adult=false&include_video=false&page=3",

		data:
		{
			format: "json"
		},

		success: function (response)
		{

			var elems = document.getElementsByClassName("single-poster-holder");
			for (j = 0; j < count; j++)
			{




				elems[j].getElementsByClassName("single-poster-layer_bottom")[0].alt = response.results[j].title;

				elems[j].getElementsByClassName("single-poster-layer_top")[0].getElementsByClassName("single-poster-layer_top")[0].getElementsByTagName("h1")[0].innerHTML = response.results[j].title;

				elems[j].getElementsByClassName("single-poster-layer_top")[0].getElementsByClassName("single-poster-layer_top")[0].getElementsByTagName("h3")[0].innerHTML = "★" + response.results[j].vote_average + "/10";






				$.ajax(
				{

					url: "https://api.themoviedb.org/3/movie/" + response.results[j].id + "?api_key=3f51c3329a20300b741b815efe1b5daa&append_to_response=release_dates",


					data:
					{
						format: "json"
					},


					indexValue: j,
					success: function (response, indexValue)
					{
					




						for (k = 0; k < count; k++)
						{

							if (response.release_dates.results[k].iso_3166_1 == "US")
							{

								document.getElementsByClassName("single-poster-age-rating")[this.indexValue].innerHTML =
									response.release_dates.results[k].release_dates[0].certification;
								break;
							}
						}

						if (document.getElementsByClassName("single-poster-age-rating")[this.indexValue].innerHTML == "")
						{
							document.getElementsByClassName("single-poster-age-rating")[this.indexValue].style.display = "none";
						}




						elems[this.indexValue].getElementsByClassName("single-poster-layer_bottom")[0].onload =
								RemoveFeaturedLoading(this.indexValue);



							$(elems[this.indexValue].getElementsByClassName("single-poster-layer_bottom")[0]).fadeOut(300, swapFeaturedImages(this.indexValue, "https://image.tmdb.org/t/p/w500/" + response.poster_path));





							if (response.backdrop_path)
							{
								document.getElementsByClassName("fanart-horizontal-image")[this.indexValue].src =
								"https://image.tmdb.org/t/p/w1280/" + response.backdrop_path;
							}



					}
				});






			}
		}
	});


}

function swapFeaturedImages(ind, sr)
{
	var elems = document.getElementsByClassName("single-poster-holder");

	setTimeout(function ()
	{

		elems[ind].getElementsByClassName("single-poster-layer_bottom")[0].src = sr;
		elems[ind].getElementsByClassName("single-poster-layer_bottom")[0].onload = fadeinFeaturedImages(ind);

	}, 310);


}

function fadeinFeaturedImages(ind)
{
	var elems = document.getElementsByClassName("single-poster-holder");
	setTimeout(function ()
	{
		$(elems[ind].getElementsByClassName("single-poster-layer_bottom")[0]).fadeIn(800);
	}, 310);
}

function RemoveFeaturedLoading(ind)
{
	var elems = document.getElementsByClassName("single-poster-holder");
	elems[ind].classList.remove("disabledHover");
	elems[ind].getElementsByTagName("img")[0].style.filter = "hue-rotate(0deg)";





}


function createFeatured(count)
{

	for (i = 0; i < count; i++)
	{
		var single_poster_holder = document.createElement("div");
		single_poster_holder.classList.add("single-poster-holder");
		var posterImg = document.createElement("img");
		posterImg.classList.add("single-poster-layer_bottom");
		var single_poster_layer_top = document.createElement("div");
		single_poster_layer_top.classList.add("single-poster-layer_top");
		var bannerImg = document.createElement("img");
		bannerImg.classList.add("fanart-horizontal-image");
		bannerImg.classList.add("single-poster-layer_bottom");
		var single_poster_layer_top_2 = document.createElement("div");
		single_poster_layer_top_2.classList.add("single-poster-layer_top");
		var title = document.createElement("h1");
		var rating = document.createElement("h3");
		var age = document.createElement("div");
		age.classList.add("single-poster-age-rating");

		if (i >= 4)
		{
			single_poster_holder.classList.add("right-poster");
		}


		posterImg.src = "img/ajax-loader.gif";
		posterImg.style.filter = "hue-rotate(" + (Math.random() * 360) + 1 + "deg)";
		single_poster_holder.classList.add("disabledHover");


		single_poster_layer_top_2.appendChild(title);
		single_poster_layer_top_2.appendChild(rating);
		single_poster_layer_top_2.appendChild(age);

		single_poster_layer_top.appendChild(bannerImg);
		single_poster_layer_top.appendChild(single_poster_layer_top_2);

		single_poster_holder.appendChild(posterImg);
		single_poster_holder.appendChild(single_poster_layer_top);

		document.getElementsByClassName("posters-holder")[0].appendChild(single_poster_holder);
	}
}


