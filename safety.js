
        var href = $(location).attr("href");
        var pathname = $(location).attr("pathname");
        var search = $(location).attr("search");
        var searchTemp = "";

        $(document).ready(function () {

            InitdivMyinfoDialog(0);
            InitdivDelmemberDialog(0);
            InitdivLockDialog(0);

            $("#cboLabList").change(function () {
                //alert(href);
                //alert(pathname);
                //alert(search);
                var isLabNoQueryStringExist = false;

                searchTemp = search.replace(/^\?/, '');
                // search에 mode=tab&file=10_chap10.txt이 저장됩니다.
                searchTemp = searchTemp.split('&')
                // 이제 search는 mode=tab과 file=10_chap10.txt의 배열입니다.
                var pair, key, value;
                var query = "";
                
                for (var i = 0; i < searchTemp.length; i += 1) {
                    pair = searchTemp[i].split('=');
                    key = pair[0];
                    value = pair[1];
                    // 이제 key(mode, file)와 value(tab, 10_chap10.txt)을 얻었고
                    // 이를 코드에 이용할 수 있습니다.

                    if (key.toUpperCase() != "LABNO") {
                        query = query + searchTemp[i] + "&";
                    }

                    
                    if (key.toUpperCase() == "LABNO") {
                        isLabNoQueryStringExist = true;
                    }
                }
                //alert(query);
                if (query == "") {
                    query = "LabNo=" + $("#cboLabList").val();
                }
                else {
                    query = query + "LabNo=" + $("#cboLabList").val();
                }

                InsLabUserinfo ($("#cboLabList").val());


                if(isLabNoQueryStringExist == true)
                {
                    window.open(pathname + "?" + query, "yuhome", "width=1200, height=1100, status=0, location=0, menubar=0, scrollbars=0, resizable = 1, scrollbars = 1 ");
                    //document.location = pathname + "?" + query;
                    //alert(pathname + "?" + query);
                }
                else
                {
                    
                    Header_LabPopUp($("#cboLabList").val());
                }
                
            });

        
            var guideWindow = $('.Integration_lock_guide');
            var layerWindow = $('.Integration_quick_menu_layer');
            var descWindow = $('.Integration_desc_layer');
            var adminFunction = $('.Integration_admin_function');

            // Show Hide

            $('.Integration_remote_lock_,.Integration_lock_guide').mouseover(function(){
                
                guideWindow.addClass('view');

            });

            $('.Integration_remote_lock_,.Integration_lock_guide').mouseout(function(){

                guideWindow.removeClass('view');

            });
            $('.Integration_guide_close').click(function(){

                guideWindow.removeClass('view');

            });


            // 퀵메뉴
            // Show Hide

            $('.Integration_quick_menu,.Integration_quick_menu_layer').mouseover(function(){

                layerWindow.addClass('view');

            });

            $('.Integration_quick_menu,.Integration_quick_menu_layer').mouseout(function(){

                layerWindow.removeClass('view');

            });
            $('.Integration_quick_menu_close').click(function(){

                layerWindow.removeClass('view');

            });



            
            

            $("#cboHeaderIdentify").change(function () {

                $.ajax({
                    type: 'POST',
                    url: "/Account/IdentifyChange",
                    data: { "identify": $("#cboHeaderIdentify").val() },
                    beforeSend: function (xmlHttpRequest) {
                        cfShowBlock(true);
                    },
                    error: function (xhr, textStatus, errorThrown) {
                        //에러 메시지 처리
                        alert('요청 중 서버에서 에러가 발생하였습니다.');
                    },
                    success: function (data, textStatus) {
                        //서버 에러 체크
                        if (data.Success == true) {
                            alert("변경 되었습니다.");
                            //location.reload();

                            // 첫화면으로 이동
                            location.href = "/";
                        }
                        else {
                            alert(data.Message);
                            return false;
                        }
                    },
                    complete: function (xhr, textStatus) {
                        //처리중 UI 제거
                        cfHideBlock();
                    }
                });

                return false;
            });



        });


 
   
        function InsLabUserinfo (labno) {
           
            $.ajax({
                type: 'POST',
                url: "/Home/InsLabuserinfo",
                data: { "LabNo": labno },
                beforeSend: function (xmlHttpRequest) {
                    cfShowBlock(true);
                },
                error: function (xhr, textStatus, errorThrown) {
                    //에러 메시지 처리
                    alert('요청 중 서버에서 에러가 발생하였습니다.');
                },
                success: function (data, textStatus) {
                    if (data.IsSuccess == true) {
                        //GetCreateSearchList($("#CreateSearchCurrentPageIndex").val());
                        //  Init();
                    }
                    else {
                        alert(data.Msg);
                    }
                },
                complete: function (xhr, textStatus) {
                    //처리중 UI 제거
                    cfHideBlock();
                }
            });
           

            //  return false;
        }
        ///

        function InitdivMyinfoDialog(userno) {
            
            $("#divMyinfo").dialog({
                autoOpen: false,
                height: 850,
                width: 500,
                modal: true,
                open: function (event, ui) {
                    $.ajax({
                        type: "POST",
                        url: "/Home/Myinfo",
                        data: { "UserNo": userno },
                        beforeSend: function (xmlHttpRequest) {
                            cfShowBlock(true);
                        },
                        success: function (data) {

                            $("#divMyinfo").html(data);
                        },
                        error: function (xhr, status, error) {
                            alert(error);

                            return false;
                        },
                        complete: function (xhr, textStatus) {
                            //처리중 UI 제거
                            cfHideBlock();
                        }
                    });
                },
                close: function (event, ui) {
                    //    $("#divEdit").html("");
                    //  GetList($("#CurrentPageIndex").val());
                }
            });

            return false;

        }



        function InitdivDelmemberDialog(userno) {
            $("#divDelmember").dialog({
                autoOpen: false,
                height: 550,
                width: 500,
                modal: true,
                open: function (event, ui) {
                    $.ajax({
                        type: "POST",
                        url: "/Home/Delmember",
                        data: { "UserNo": userno },
                        beforeSend: function (xmlHttpRequest) {
                            cfShowBlock(true);
                        },
                        success: function (data) {

                            $("#divDelmember").html(data);
                        },
                        error: function (xhr, status, error) {
                            alert(error);

                            return false;
                        },
                        complete: function (xhr, textStatus) {
                            //처리중 UI 제거
                            cfHideBlock();
                        }
                    });
                },
                close: function (event, ui) {
                    //    $("#divEdit").html("");
                    //  GetList($("#CurrentPageIndex").val());
                }
            });

            return false;

        }



        function InitdivLockDialog(labno) {

            $("#divLock").dialog({
                autoOpen: false,
                height: 350,
                width: 500,
                modal: true,
                open: function (event, ui) {
                    $.ajax({
                        type: "POST",
                        url: "/Home/SafeLock",
                        data: { "LabNo": labno },
                        beforeSend: function (xmlHttpRequest) {
                            cfShowBlock(true);
                        },
                        success: function (data) {

                            $("#divLock").html(data);
                        },
                        error: function (xhr, status, error) {
                            alert(error);

                            return false;
                        },
                        complete: function (xhr, textStatus) {
                            //처리중 UI 제거
                            cfHideBlock();
                        }
                    });
                },
                close: function (event, ui) {
                   
                }
            });

            return false;
        }
        
        
        //내정보창열기 
        function OpenMyinfo(userno) {
            CloseDialog2();
            InitdivMyinfoDialog(userno);
       …