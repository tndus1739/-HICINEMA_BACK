(function($) {
  'use strict';
  $(function() {
    var body = $('body');
    var contentWrapper = $('.content-wrapper');
    var scroller = $('.container-scroller');
    var footer = $('.footer');
    var sidebar = $('.sidebar');

    //Add active class to nav-link based on url dynamically
    //Active class can be hard coded directly in html file also as required
    var current = location.pathname.split("/").slice(-1)[0].replace(/^\/|\/$/g, '');
    let check = false;
    $('.nav li a', sidebar).each(function() {
      var $this = $(this);
      if (current === "") {
        //for root url
        if ($this.attr('href').indexOf("index.html") !== -1) {
          $(this).parents('.nav-item').last().addClass('active');
          if ($(this).parents('.sub-menu').length) {
            $(this).closest('.collapse').addClass('show');
            $(this).addClass('active');
            check = true;
          }
        }
      } else {
        //for other url
        if ($this.attr('href').indexOf(current) !== -1) {
          $(this).parents('.nav-item').last().addClass('active');
          if ($(this).parents('.sub-menu').length) {
            $(this).closest('.collapse').addClass('show');
            $(this).addClass('active');
            check = true;
          }
        }
      }

      //  custom js - bmh ( 언더바(_) 앞이 같으면 리스트 페이지로 연결되었던 sidebar active 오류생기면 주석해주세요)
      if(check === false) {
        let rt = $(this).attr('href').substring($(this).attr('href').lastIndexOf("/") + 1);
        let r = rt.split("_")[0];
        let cur = current.split("_")[0]
        if(r === cur) {
          $(this).closest('.collapse').addClass('show');
          $(this).addClass('active');
          check = true;
        }
      }
    })

    //Close other submenu in sidebar on opening any

    sidebar.on('show.bs.collapse', '.collapse', function() {
      sidebar.find('.collapse.show').collapse('hide');
    });


    //Change sidebar and content-wrapper height
    applyStyles();

    function applyStyles() {
      //Applying perfect scrollbar
      if (!body.hasClass("rtl")) {
        if ($('.tab-content .tab-pane.scroll-wrapper').length) {
          const settingsPanelScroll = new PerfectScrollbar('.settings-panel .tab-content .tab-pane.scroll-wrapper');
        }
        if ($('.chats').length) {
          const chatsScroll = new PerfectScrollbar('.chats');
        }
      }
    }

    //checkbox and radios
    $(".form-check label,.form-radio label").append('<i class="input-helper"></i>');

    //fullscreen
    $("#fullscreen-button").on("click", function toggleFullScreen() {
      if ((document.fullScreenElement !== undefined && document.fullScreenElement === null) || (document.msFullscreenElement !== undefined && document.msFullscreenElement === null) || (document.mozFullScreen !== undefined && !document.mozFullScreen) || (document.webkitIsFullScreen !== undefined && !document.webkitIsFullScreen)) {
        if (document.documentElement.requestFullScreen) {
          document.documentElement.requestFullScreen();
        } else if (document.documentElement.mozRequestFullScreen) {
          document.documentElement.mozRequestFullScreen();
        } else if (document.documentElement.webkitRequestFullScreen) {
          document.documentElement.webkitRequestFullScreen(Element.ALLOW_KEYBOARD_INPUT);
        } else if (document.documentElement.msRequestFullscreen) {
          document.documentElement.msRequestFullscreen();
        }
      } else {
        if (document.cancelFullScreen) {
          document.cancelFullScreen();
        } else if (document.mozCancelFullScreen) {
          document.mozCancelFullScreen();
        } else if (document.webkitCancelFullScreen) {
          document.webkitCancelFullScreen();
        } else if (document.msExitFullscreen) {
          document.msExitFullscreen();
        }
      }
    })
  });
})(jQuery);

// custom js - bmh (체크박스 - table 형식의 리스트)
(function () {
  let all = document.getElementsByClassName('all_check');

  for (let a of all) {
    a.addEventListener('change', function () {
      let parent = a.parentNode;
      let bro;
      let table;
      while (parent) {
        if (parent.tagName === 'TABLE') {
          table = parent;
          break;
        }
        parent = parent.parentNode
      }
      bro = parent.querySelectorAll('td input[type="checkbox"]');
      checkbox_control(a, bro);
      for (let b of bro) {
        b.addEventListener('change', function () {
          let bro_cnt = parent.querySelectorAll('td input[type="checkbox"]:checked').length
          a.checked = (bro_cnt === bro.length);
        })
      }
    })
  }

  function checkbox_control(all, bro) {
    console.log(all)
    console.log(bro)
    if (all.checked) {
      for (let b of bro) {
        b.checked = true
      }
    } else {
      for (let b of bro) {
        b.checked = false;
      }
    }
  }
})();