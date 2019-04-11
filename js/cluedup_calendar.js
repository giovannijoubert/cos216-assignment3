 

 var month = new Array();
 month[0] = "January";
 month[1] = "February";
 month[2] = "March";
 month[3] = "April";
 month[4] = "May";
 month[5] = "June";
 month[6] = "July";
 month[7] = "August";
 month[8] = "September";
 month[9] = "October";
 month[10] = "November";
 month[11] = "December";

 var loadCal = function (m, tt)
 {
 	return function curried_func(e)
 	{
 		$(".calendar_events").fadeOut("slow", function ()
 		{
 			$(".ce_loader").fadeIn("slow");
 			var myNode = document.getElementsByClassName("calendar_events");
 			myNode[0].innerHTML = "";
 			loadCalendar(m, tt);

 		});
 	};
 };

 function bindCalendarButtons(prevMonth, nextMonth, TodayDate)
 {

 	$("#prev").unbind('click');
 	$("#prev").bind('click', loadCal(prevMonth, false));

 	$("#today").unbind('click');

 	$("#today").bind('click', loadCal(TodayDate, true));

 	$("#next").unbind('click');

 	$("#next").bind('click', loadCal(nextMonth, false));
 }

 var t = false;
 var p = false;

 function loadCalendar(loadDate, tt)
 {
          $("#DownloadCal").addClass("DisableDownload");
 	$(".right-desc").fadeOut("slow", function ()
 	{
 		$(".right-desc-loader").fadeIn("slow");
 	});
 	t = false;
 	t = tt;
 	p = false;
 	if (loadDate == "datepicker")
 	{
 		$(".calendar_events").fadeOut("fast", function ()
 		{
 			$(".ce_loader").fadeIn("slow");
 		});
 		var myNode = document.getElementsByClassName("calendar_events");
 		myNode[0].innerHTML = "";
 		loadDate = new Date(document.getElementById("datepicker").value);
 		p = true;
 	}

 	var TodayDate = new Date();
 	if (!loadDate)
 	{
 		loadDate = TodayDate;
 		t = true;
 	}
 	else
 	{
 		loadDate = new Date(loadDate);
 	}

 	document.getElementsByClassName("header_title")[0].innerHTML = month[loadDate.getMonth()] + " " + loadDate.getFullYear();

 	loadCalendarMovies(loadDate);



 }

 var promises = [];

 function loadCalendarMovies(loadDate)
 {

 	var d = loadDate.getDate();
 	var m = loadDate.getMonth();
 	var y = loadDate.getFullYear();

 	var lastDay = new Date();
 	lastDay.setFullYear(y, m + 1, 0);

 	promises.length = 0;
 	for (i = 1; i <= lastDay.getDate(); i++)
 	{
 		var monthURLString = (m + 1).toString();
 		var dayURLString = i.toString();
 		if (m + 1 < 10)
 		{
 			monthURLString = "0" + monthURLString;
 		}
 		if (i < 10)
 		{
 			dayURLString = "0" + dayURLString;
 		}
 		var promise = $.get("https://api.themoviedb.org/3/discover/movie?api_key=3f51c3329a20300b741b815efe1b5daa&language=en-US&sort_by=popularity.desc&include_adult=false&include_video=true&page=1&primary_release_date.gte=" + y + "-" + monthURLString + "-" + dayURLString + "&primary_release_date.lte=" + y + "-" + monthURLString + "-" + dayURLString + "&release_date.gte=" + y + "-" + monthURLString + "-" + dayURLString + "&release_date.lte=" + y + "-" + monthURLString + "-" + dayURLString).done(function (result, statusText, jqxhr) {

 		}).always(function () {});

 		promises.push(promise);
 	}

 	$.when.apply($, promises).done(function ()
 	{
 		ProcessMonthMoviesResult(lastDay);
 	}).fail(function () {});

 }



 var loadMovie = function (m)
 {
 	return function curried_func(e)
 	{
 		loadCalendarMovieVideo(m);

 	};
 };

 function bindEventClick(MovieID)
 {
 	$("#" + MovieID).unbind('click');
 	$("#" + MovieID).bind('click', loadMovie(MovieID));

 }



 function loadCalendarMovieVideo(MovieID)
 {
 	$(".right-desc").fadeOut("slow", function ()
 	{
 		$(".right-desc-loader").fadeIn("slow");
 	});
 	setTimeout(function ()
 	{

 		var event_item = document.getElementById(MovieID);
 		var elem = document.getElementsByClassName("active_event_item");
 		for (i = 0; i < elem.length; i++)
 		{
 			elem[i].classList.remove("active_event_item");
 		}

 		event_item.classList.add("active_event_item");
 		var xhttp = new XMLHttpRequest();
 		xhttp.onreadystatechange = function ()
 		{
 			if (this.readyState == 4 && this.status == 200)
 			{

 				var JSONObj = JSON.parse(this.responseText);
 				var yt = document.getElementsByClassName("youtube");

 				if (!JSONObj.results[0])
 				{
 					yt[0].style.display = "none";

 				}
 				else
 				{

 					yt[0].src = "http://www.youtube.com/embed/" + JSONObj.results[0].key;
 					yt[0].style.display = "block";
 				}

 			}
 		};

 		xhttp.open("GET", "https://api.themoviedb.org/3/movie/" + MovieID + "/videos?api_key=3f51c3329a20300b741b815efe1b5daa&language=en-US", true);
 		xhttp.send();

 		loadCalendarMovieInfo(MovieID);
 	}, 600);

 }

 function loadCalendarMovieInfo(MovieID)
 {

 	var xhttp = new XMLHttpRequest();
 	xhttp.onreadystatechange = function ()
 	{
 		if (this.readyState == 4 && this.status == 200)
 		{

 			var JSONObj = JSON.parse(this.responseText);

 			document.getElementsByClassName("movie_title")[0].innerHTML = JSONObj.original_title;

 			document.getElementsByClassName("movie_desc")[0].innerHTML = JSONObj.overview;

 			var release = new Date(JSONObj.release_date);
 			var d = release.getDate();
 			var m = release.getMonth();
 			var y = release.getFullYear();
 			var dateReadable;

 			dateReadable = d + getOrdinalFor(d) + " " + month[m] + " " + y;



 			document.getElementsByClassName("movie_release")[0].innerHTML = dateReadable;
 			$(".cl_title").fadeOut("slow", function ()
 			{
 				document.getElementsByClassName("cl_title")[0].innerHTML = dateReadable;
 				$(".cl_title").fadeIn("slow");
 			});

 			$(".cl_copy").fadeOut("slow", function ()
 			{
 				document.getElementsByClassName("cl_copy")[0].innerHTML = JSONObj.original_title;
 				$(".cl_copy").fadeIn("slow");
 			});

 			var ageRestriction = JSONObj.release_dates.results[0].release_dates[0].certification;

 			if (ageRestriction)
 			{
 				document.getElementsByClassName("single-poster-age-rating")[0].innerHTML = ageRestriction;
 			}
 			else
 			{
 				document.getElementsByClassName("single-poster-age-rating")[0].innerHTML = "N/A";
 			}
 			setTimeout(function ()
 			{

 				$(".right-desc-loader").fadeOut("slow", function ()
 				{
 					$(".right-desc").fadeIn("slow");
 				});

 			}, 1000);

 		}
 	};

 	xhttp.open("GET", "https://api.themoviedb.org/3/movie/" + MovieID + "?api_key=3f51c3329a20300b741b815efe1b5daa&language=en-US&append_to_response=release_dates", true);
 	xhttp.send();
 }

 function ProcessMonthMoviesResult(lastDay)
 {
     


 	var m = lastDay.getMonth();
 	var y = lastDay.getFullYear();
 	var TodayDate = new Date();
 	var nextMonth = new Date();
 	nextMonth.setFullYear(y, m + 1, 1);

 	var prevMonth = new Date();
 	prevMonth.setFullYear(y, m - 1, 1);
 	bindCalendarButtons(prevMonth, nextMonth, TodayDate);
 	var pickerSuccess = false;


 	var pickerDate = new Date(document.getElementById("datepicker").value);

 	for (j = 0; j < lastDay.getDate(); j++)
 	{
 		if (promises[j].responseJSON.results[0])
 		{

 			var event_item = document.createElement("div");
 			event_item.classList.add("event_item");
 			var MovieID = promises[j].responseJSON.results[0].id;
 			event_item.id = MovieID;

 			var ei_Dot = document.createElement("div");
 			ei_Dot.classList.add("ei_Dot");

 			ei_Dot.innerHTML = (j + 1) + getOrdinalFor(j + 1);

 			event_item.appendChild(ei_Dot);

 			var ei_Title = document.createElement("div");
 			ei_Title.classList.add("ei_Title");
 			ei_Title.innerHTML = promises[j].responseJSON.results[0].title;
 			event_item.appendChild(ei_Title);

 			document.getElementsByClassName("calendar_events")[0].appendChild(event_item);
 			bindEventClick(MovieID);
 			if (t)
 			{
 				if (j + 1 == TodayDate.getDate())
 				{
 					$(".event_item:last-child").trigger("click");
 				}
 			}
 			else if (p)
 			{
 				if (j + 1 == pickerDate.getDate())
 				{
 					$(".event_item:last-child").trigger("click");
 					pickerSuccess = true;
 				}
 			}
 			else
 			{

 				$(".event_item").eq(0).trigger("click");
 			}

 		}
 	}
 	if (p && !pickerSuccess)
 	{
 		alert("No releases found for " + pickerDate.getDate() + getOrdinalFor(pickerDate.getDate()) + " " + month[pickerDate.getMonth()] + " " + pickerDate.getFullYear());
 	}
 	setTimeout(function ()
 	{

 		$(".ce_loader").fadeOut("slow", function ()
 		{
 			$(".calendar_events").fadeIn("slow");
                $("#DownloadCal").removeClass("DisableDownload");
 		});

 	}, 200);
 }

function downloadCalendar(){
    
var monthName = document.getElementsByClassName("header_title")[0].innerHTML;
var movieDays = document.getElementsByClassName("ei_Dot");
var moviesTitles = document.getElementsByClassName("ei_Title");
    var data = []
    for (i = 0; i < moviesTitles.length; i++){
        data[i] = new Array(2);
        data[i][0] = movieDays[i].innerHTML + " " + monthName;
        data[i][1] = moviesTitles[i].innerHTML;
        
    }



var csvContent = '';
data.forEach(function(infoArray, index) {
  dataString = infoArray.join(';');
  csvContent += index < data.length ? dataString + '\n' : dataString;
});

var download = function(content, fileName, mimeType) {
  var a = document.createElement('a');
  mimeType = mimeType || 'application/octet-stream';

  if (navigator.msSaveBlob) { 
    navigator.msSaveBlob(new Blob([content], {
      type: mimeType
    }), fileName);
  } else if (URL && 'download' in a) { 
    a.href = URL.createObjectURL(new Blob([content], {
      type: mimeType
    }));
    a.setAttribute('download', fileName);
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  } else {
    location.href = 'data:application/octet-stream,' + encodeURIComponent(content); 
  }
}

download(csvContent, monthName + '_CluedUP_Calendar.csv', 'text/csv;encoding:utf-8');
}


 function getOrdinalFor(value)
 {
 	tenRemainder = value % 10;
 	switch (tenRemainder)
 	{
 	case 1:
 		return "st";
 	case 2:
 		return "nd";
 	case 3:
 		return "rd";
 	default:
 		return "th";
 	}
 }