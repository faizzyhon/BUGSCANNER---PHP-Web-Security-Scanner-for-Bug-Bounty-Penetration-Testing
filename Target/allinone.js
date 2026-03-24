// FOR ALL --------------------------
$('.ui.dropdown').dropdown();
$('select.dropdown').dropdown();
$('.ui.radio.checkbox').checkbox();

function logout() {
    if (confirm("logout?")) {
        window.location.href = "/info.php?logout";
    }
}

function count_cart() {
    $.ajax({
        type: "GET",
        url: "/cc_basket.php?cart_count",
        success: function (msg) {
            $("#cartcount,#cart_count_cards").text(msg);
        }
    });
}

function balance() {
    $.ajax({
        type: "GET",
        url: "/info.php?get_balance",
        success: function (msg) {
            $("#balance").text(msg);
        },
        error: function () {
            setTimeout(function () {
                balance();
            }, 5000);
        }
    });
}

//___________________________________

// LOGIN --------------------------
$("#signin").on("click", function () {
    sign_in();
});

function sign_in() {
    var user = $("#username").serialize();
    var pass = $("#password").serialize();
    var vkey = $("#mcaptcha__token").serialize();
    var vkey2 = $("#mcaptcha_token").serialize();

    $.ajax({
        type: "POST",
        url: "/login.php?login",
        data: user + "&" + pass + "&" + vkey + "&" + vkey2,
        beforeSend: function () {
            $('#signin').text('...');
        },
        success: function (result) {
            if (result === '5') {
                window.location = "/index.php";
            }
            if (result === '3') {
                alert('no such account exists');
            }
            if (result === '0') {
                alert('many requests by ip');
            }
            if (result === '1') {
                alert('many requests by username');
            }
        },
        complete: function () {
            $("#signin").text("Sign In");
        }
    });
}

//___________________________________

// REGISTRATION ---------------------
function register(captcha) {
    $.ajax({
        dataType: 'json',
        type: "POST",
        url: "/login.php?register=" + captcha,
        beforeSend: function () {
            $('#register_modal').modal('show');
            chb2 = 1;
            $('#registration_block').html('');
        },
        success: function (result) {
            if (result.register === 'ok') {
                $('#registration_block').html('' +
                    '<tr>\n' +
                    '          <td class="six wide">USERNAME:</td>\n' +
                    '          <td id="generated_username">generating...</td>\n' +
                    '        </tr>\n' +
                    '        <tr>\n' +
                    '          <td>PASSWORD:</td>\n' +
                    '          <td id="generated_password">generating...</td>\n' +
                    '        </tr>');
                $('#generated_username').text(result.username);
                $('#generated_password').text(result.password);
                $('#username').val(result.username);
                $('#password').val(result.password);
            }
            if (result.register === 'closed') {
                $('#registration_block').html(
                    '<tr>\n' +
                    '<td colspan="2" class="six wide center aligned">Registration disabled.</td>\n' +
                    '</tr>');
            }
            if (result.register === 'captchafail') {
                $('#registration_block').html(
                    '<tr>\n' +
                    '<td colspan="2" class="six wide center aligned">Captcha failed.</td>\n' +
                    '</tr>');
            }
        },
        complete: function () {
            chb2 = 0;
        }
    });
}

//___________________________________

// BIN     --------------------------
function clearbintext() {
    $('#mybins').val('');
}

function bin_search() {
    $.ajax({
        dataType: "json",
        type: 'post',
        url: '/bin_search.php?bininfo',
        data: 'data=' + $('#mybins').val(),
        beforeSend: function () {
            $('#bininfo').addClass('loading');
            $('#bintext').html('');
        },
        success: function (result) {
            if (result.length > 0) {
                $.each(result, function (c, d) {
                    $('#bintext').append('<tr>' +
                        '<td>' + d.bin + '</td>' +
                        '<td>' + d.country + '</td>' +
                        '<td>' + d.depart + '</td>' +
                        '<td>' + d.brand + '</td>' +
                        '<td>' + d.type + '</td>' +
                        '<td>' + d.level + '</td>' +
                        '<td>noinfo</td>' +
                        '</tr>');
                });
            }
        },
        complete: function () {
            $('#bininfo').removeClass('loading');
        }
    });
}

//___________________________________


// BUY CC     --------------------------
function insert_list(type, result) {
    $.each(result, function (ind, item) {
        if (type === 'category') {
            if (item.date === '0000-00-00' || item.date === '--') {
                item.date = '';
            }

            if (item.validreal !== '') {
                item.valid = 'OnlineCategoryValid: ' + item.validreal + '%';
            }
            if (item.counter == 0) {
                item.counter = 0.5;
            }

            $('#card' + type + 'menu').append('<div class="ui item" data-value="' + item.id + '">' +
                '<small>' + item.date + '</small>  ' + item.value + '  ~<small>' + item.counter + 'k cards</small></div>');
        }
        if (type === 'country') {
            $('#card' + type + 'menu').append('<div class="ui item" data-value="' + item.id + '">' + item.value + '</div>');
        }
        if (type === 'brand' || type === 'type' || type === 'level' || type === 'city' || type === 'state') {
            $('#card' + type + 'menu').append('<div class="ui item" data-value="' + item.id + '">' + item.value + '</div>');
        }
    });
}

function get_list(index, name, path) {

    var form_info = {
        addrex: $('#cardaddr').val(), phone: $('#phone').val(), email: $('#email').val(),
        selltype: $('#selltype').val(), cvv: $('#cardcvv').val(),
        category: $('#categoryid').val(), country: $('#cardcountry').val(),
        brand: $('#cardbrand').val(), type: $('#cardtype').val(), level: $('#cardlevel').val(),
        bin: $('#cardbin').val(), state: $('#cardstate').val(),
        city: $('#cardcity').val(), zip: $('#cardzip').val()
    };
    var data = $.param(form_info);

    $.ajax({
        dataType: "json",
        async: true,
        type: 'post',
        url: '/cc_buy.php?' + path,
        data: data,
        beforeSend: function () {
            $('#pageselection').dropdown('restore defaults');
            $('#' + path + 'block').addClass('loading');
            $('#' + index + ' *').remove();
        },
        success: function (result) {
            $('#' + index + ' *').remove();
            //if (path !== 'category'){
            $('#' + index).html('<div class="item" data-value="0">' + name + '</div>');
            // }
            insert_list(path, result);
        },
        error: function () {
            $('#' + index + ' *').remove();
            setTimeout(function () {
                get_list(index, name, path);
            }, 5000);
        },
        complete: function () {
            $('#' + path + 'block').removeClass('loading');
        }
    });
}


function change_firts_settings() {
    $('#categoryblock,#countryblock,#stateblock,#cityblock').dropdown('clear', 'restore defaults');
    $('#cardcategorymenu *,#cardcountrymenu *,#cardstatemenu *,#cardcitymenu *').remove();
    get_list('cardcategorymenu', 'All', 'category');
}

function change_category() {
    $('#countryblock,#stateblock,#cityblock').dropdown('clear', 'restore defaults');
    $('#cardstatemenu *,#cardcitymenu *').remove();
    get_list('cardcountrymenu', 'All', 'country');
}

function change_country() {
    $('#stateblock,#cityblock').dropdown('clear', 'restore defaults');
    $('#cardstatemenu *,#cardcitymenu *').remove();

    if ($('#cardcountry').val() !== '0' && $('#cardcountry').val() !== '') {
        get_list('cardstatemenu', 'All', 'state');
    }
}

function change_brand() {
    if ($('#cardcountry').val() !== '0' && $('#cardcountry').val() !== '') {
        $('#stateblock,#cityblock').dropdown('clear', 'restore defaults');
        $('#cardstatemenu *,#cardcitymenu *').remove();
        if ($('#cardbrand').val() !== '') {
            get_list('cardstatemenu', 'All', 'state');
        }
    }
}

function change_type() {
    if ($('#cardcountry').val() !== '0' && $('#cardcountry').val() !== '') {
        $('#stateblock,#cityblock').dropdown('clear', 'restore defaults');
        $('#cardstatemenu *,#cardcitymenu *').remove();
        if ($('#cardtype').val() !== '') {
            get_list('cardstatemenu', 'All', 'state');
        }
    }
}

function change_level() {
    if ($('#cardcountry').val() !== '0' && $('#cardcountry').val() !== '') {
        $('#stateblock,#cityblock').dropdown('clear', 'restore defaults');
        $('#cardstatemenu *,#cardcitymenu *').remove();
        if ($('#cardlevel').val() !== '') {
            get_list('cardstatemenu', 'All', 'state');
        }
    }
}

function change_state() {
    $('#cityblock').dropdown('clear', 'restore defaults');
    $('#cardcitymenu *').remove();
    if ($('#cardstate').val() !== '') {
        get_list('cardcitymenu', 'All', 'city');
    }
}

function view_card_list(page = 1) {
    var form_info = {
        addrex: $('#cardaddr').val(), phone: $('#phone').val(), email: $('#email').val(),
        selltype: $('#selltype').val(), cvv: $('#cardcvv').val(),
        page: $('#pageco').val(), perpage: $('#onpage').val(), category: $('#categoryid').val(),
        country: $('#cardcountry').val(),
        brand: $('#cardbrand').val(), type: $('#cardtype').val(), level: $('#cardlevel').val(),
        bin: $('#cardbin').val(), state: $('#cardstate').val(),
        city: $('#cardcity').val(), zip: $('#cardzip').val(), bank: $('#cardbank').val(), selleruse: $('#selleruse').val()
    };
    var data = $.param(form_info);

    $.ajax({
        dataType: "json",
        type: 'post',
        url: '/cc_buy.php?cards',
        data: data,
        beforeSend: function () {
            $('#panelbuyer').addClass('loading');
        },
        success: function (result) {
            $('#cardbody *').remove();
            if (result[0]['lock'] === '1') {
                tinfo('tbl_nocard', 'Query limit. Try later. (limit:30sec)');
            } else {
                paginations(result[0]['count']);
                $(".pageblock").css("display", "");
                result.shift();
                $('#cardbody *').remove();
                if (result.length === 0) {
                    tinfo('tbl_nocard', 'No info');
                }
                $.each(result, function (ind, item) {
                    add_card_line(item);
                });
            }
        },
        complete: function () {
            $('#panelbuyer').removeClass('loading');
        }
    });
}

function setOnPage(pp) {
    $('#onpage50,#onpage100,#onpage200,#onpage300').removeClass('active');
    $('#onpage').val(pp);
    $('#onpage' + pp).addClass('active');
}

function paginations(num) {
    if (num > 300) {
        num = 300;
    }
    $('#pagmenu *').remove();
    for (var i = 1; i <= num; i++) {
        $('#pagmenu').append('<div class="item" data-value="' + i + '">' + i + '</div>');
    }
}

function tinfo(name, text) {
    $('#cardbody').append('<tr id="' + name + '">\n' +
        '    <th colspan="14" style="text-align: center;">' + text + '</th>\n' +
        '</tr>');
}


function add_card_line(item) {
    if (item.catdate === '0000-00-00' || item.catdate === '--') {
        item.catdate = '';
    }

    if ((item.expdiscount * 1) === 1) {
        item.expdiscount = 'style="background-color: lightcoral"';
    }

    validstring = 'not enough data<br>to calculate';
    if ((item.rref * 1) >= 40) {
        validstring = 'Valid: ~' + item.rref + '%<br>';
    }


    $('#cardbody').append('' +
        '<tr id="card_line_' + item.id + '" >\n' +
        '<td>' + item.bin + '<br><small>' + item.brand + '/' + item.typecard + '<br>' + item.levelcard + '</small></td>\n' +
        '<td style="text-align: left;" ' + item.expdiscount + '>' +
        '<small>Name: ' + item.fname + ' </small><br>' +
        'Exp: ' + item.month + ' / ' + item.year + '<br>' +
        '<small>CVV: ' + add_symbol(item.excvv) +
        '</small></td>\n' +
        '<td>' + item.country + '<br><small><strong>' + item.bank + '</strong><br>Base: ' + item.catdate + ' ' + item.catname + '</small></td>\n' +
        '<td style="text-align: left;"><small>Address: ' + add_symbol(item.address) + '<br>Phone: ' + add_symbol(item.phone) + '<br>eMail: ' + add_symbol(item.email) + '</small></td>\n' +
        '<td style="text-align: left;">City: ' + item.city + '<br>State: ' + item.state + '<br>Zip: ' + item.zip + '</td>\n' +
        '<td><small>' +
        validstring +
        '</small></td>\n' +
        '<td>$' + item.price + '<br><small>Refund: ' + add_symbol(item.nocheckcc) + '</small><br><small>Seller #' + item.sellernid + '</small></td>\n' +
        '<td>' +
        '<div class="ui secondary inverted buttons tiny very compact vertical" id="butbl_' + item.id + '">\n' +
        '  <button class="ui button" id="but_' + item.id + '" onclick="to_cart(' + item.id + ')">toCart</button>\n' +
        '  <button class="ui button" id="qbut_' + item.id + '" onclick="quick_buy(' + item.id + ')">Quick buy</button>\n' +
        '</div>' +
        '</td>\n' +
        '</tr>');
}

function add_symbol(id) {
    if (id === '1') {
        return 'yes';
    }
    if (id === '0') {
        return 'no';
    }
    if (id === '2') {
        return 'no';
    }
}

function to_cart(id) {
    $.ajax({
        dataType: "json",
        type: 'post',
        url: '/cc_basket.php?to_cart',
        data: 'cardid=' + id,
        success: function (result) {
            set_cart_status(result, id)
        },
        error: function () {
        }
    });
}

function add_all_to_cart() {
    var array_cardids = '';
    $.each($('#cardbody tr[id^=card_line_]'), function (ind, item) {
        array_cardids += '&id[]=' + item.id;
    });

    $.ajax({
        dataType: "json",
        type: 'post',
        url: '/cc_basket.php?add_to_cart_bulk',
        data: array_cardids,
        success: function (result) {
            $.each(result, function (ind, item) {
                set_cart_status(item, ind);
            });
        },
        error: function () {
        }
    });
    count_cart();
}

function set_cart_status(status, id) {
    if (status.toString() === '0') {
        $("#butbl_" + id).removeClass('secondary red green brown').addClass('brown');
        $("#but_" + id).text('incart');
    }
    if (status.toString() === '1') {
        count_cart();
        $("#butbl_" + id).removeClass('secondary red green brown').addClass('green');
        $("#but_" + id).text('added');
    }
    if (status.toString() === '2') {

        $("#butbl_" + id).removeClass('secondary red green brown').addClass('red');
        $("#but_" + id).text('sold');
    }
}

function set_cart_status2(status, id) {
    if (status.toString() === '0') {
        $("#butbl_" + id).removeClass('secondary red green brown').addClass('red');
        $("#qbut_" + id).text('error');
    }
    if (status.toString() === '3') {
        count_cart();
        $("#butbl_" + id).removeClass('secondary red green brown').addClass('green');
        $("#qbut_" + id).text('bought');
    }
    if (status.toString() === '2') {

        $("#butbl_" + id).removeClass('secondary red green brown').addClass('red');
        $("#qbut_" + id).text('low balance');
    }
}

function quick_buy(id) {
    $.ajax({
        dataType: "json",
        type: 'post',
        url: '/cc_buy.php?buy_one',
        data: 'cardid=' + id,
        success: function (result) {
            balance();
            if (result === 3) {
                set_cart_status2(result, id);
                quick_buy_info(id);
            } else {
                $('#information_mod').modal('show');
            }
        },
        error: function () {
        }
    });
}

function quick_buy_info(id) {
    $.ajax({
        dataType: "json",
        type: 'get',
        url: '/cc_buy.php?get_card_data=' + id,
        success: function (result) {
            if (result[0].data) {
                $('#quicktext').text(result[0].data);
                $('#quickbuy_mod').modal('show');
            } else {
                set_cart_status2(0, id);
            }
        },
        error: function () {
        }
    });
}

//___________________________________

// CART     --------------------------
function view_cart_list() {
    $.ajax({
        dataType: "json",
        type: 'get',
        url: '/cc_basket.php?cart_card_list',
        beforeSend: function () {
            $('#cartpanel').addClass('loading');
        },
        success: function (result) {
            result.shift();
            $('#cardbody *').remove();
            if (result.length === 0) {
                tinfo('tbl_nocard', 'No info');
            }
            $.each(result, function (ind, item) {
                add_card_line_cart(item);
            });
        },
        complete: function () {
            $('#cartpanel').removeClass('loading');
        }
    });
}

function add_card_line_cart(item) {
    if (item.catdate === '0000-00-00' || item.catdate === '--') {
        item.catdate = '';
    }
    $('#cardbody').append('' +
        '<tr id="card_line_' + item.id + '">\n' +
        '<td>' + item.bin + '</td>\n' +
        '<td> XX / ' + item.year + '</td>\n' +
        '<td>CVV: ' +
        add_symbol(item.excvv) +
        '</td>\n' +
        '<td>' + item.country + '<br> <small>' + 'Base: ' + item.catdate + ' ' + item.catname + '</small></td>\n' +
        '<td>' + add_symbol(item.address) + '</td>\n' +
        '<td>' + item.city + '</td>\n' +
        '<td>' + item.state + '</td>\n' +
        '<td>' + item.zip + '</td>\n' +
        '<td>' + add_symbol(item.phone) + '</td>\n' +
        '<td>' + add_symbol(item.nocheckcc) + '</td>\n' +
        '<td>$' + item.price + '</td>\n' +
        '<td>' +
        '  <button class="ui basic red tiny button" onclick="del_card(' + item.id + ')">delete</button>\n' +
        '</td>\n' +
        '</tr>');

}

function del_card(idcard) {
    $.ajax({
        type: 'post',
        url: '/cc_basket.php?del_card',
        data: 'id=' + idcard,
        success: function () {
            view_cart_list();
            get_cart_price();
            count_cart();
        },
        error: function () {
            setTimeout(function () {
                del_card(idcard);
            }, 5000);
        }
    });
}

function del_cart() {
    $.ajax({
        type: 'get',
        url: '/cc_basket.php?clear_cart',
        success: function () {
            $('#cardbody *').remove();
            count_cart();
            get_cart_price();
        },
        error: function () {
            setTimeout(function () {
                del_cart();
            }, 5000);
        }
    });
}

function get_cart_price() {
    $.ajax({
        dataType: "json",
        type: 'get',
        url: '/cc_basket.php?get_cart_price',
        success: function (result) {
            $('#cart_price_cards').text(result);
        },
        error: function () {
            $('#cart_price_cards').text('0');
            setTimeout(function () {
                get_cart_price();
            }, 5000);
        }
    });
}

function buy_card() {
    $.ajax({
        type: 'get',
        url: '/cc_basket.php?buy',
        success: function (result) {
            $('#cardbody *').remove();

            if (result === '1') {
                tinfo('tbl_nocard', 'no cards');
            }
            if (result === '2') {
                tinfo('tbl_balance_low', 'check balance');
            }
            if (result === '3') {
                tinfo('tbl_buy', 'bought cards');
                setTimeout(function () {
                    window.location = '/cc_list.php';
                }, 500);
            }
            if (result === '' || result === '7') {
                tinfo('tbl_error', 'reload page');
            }
            balance();
            count_cart();
        },
        error: function () {
            $('#cardbody *').remove();
            setTimeout(function () {
                buy_card();
            }, 5000);
        }
    });
}

//___________________________________

// CCLIST     --------------------------
function hideoffone(cid) {
    $.ajax({
        type: 'get',
        url: '/cc_list.php?seecc=' + cid,
        success: function () {
            get_card_one(cid, 1);
        },
        error: function () {
            setTimeout(function () {
                hideoffone(cid);
            }, 2000);
        }
    });
}

function get_card_one(cid) {
    $.ajax({
        type: 'get',
        dataType: "json",
        url: '/cc_list.php?get_card=' + cid,
        beforeSend: function () {
            $('#cc_status_' + cid).text('get status');
        },
        success: function (result) {
            card_line_set('', result[0]);
        },
        error: function () {
            $('#card_line_' + cid).html('<td colspan="3"><div class="center aligned">error</div></td>');
            setTimeout(function () {
                get_card_one(cid);
            }, 3000);
        }
    });
}

function card_line_set(baid = '', itemdata, type = 1) {
    let HDATA;
    let trtrf = '', trtrb = '';
    if (type === 2) {
        trtrf = '<tr id="card_line_' + itemdata['id'] + '">';
        trtrb = '</tr>';
    }
    HDATA = trtrf + '<td>' + itemdata['id'] + '</td>\n' +
        '<td class="left aligned">' + itemdata['data'] + '</td>\n' +
        '<td class="left aligned">\n' + get_card_buttons(itemdata) + '</td>' + trtrb;

    if (type === 2) {
        $('#ccday_' + baid).append(HDATA);
    } else {
        $('#card_line_' + itemdata['id']).html(HDATA);
    }
}

function get_card_buttons(itemdata) {
    let see_onclick, see_id, see_name, see_dis, stt_onclick, stt_id, stt_name, stt_dis = '';

    if (itemdata['hide'] === '0') {
        see_onclick = 'onclick="hideoffone(' + itemdata['id'] + ')"';
        see_id = 'id="seecc_' + itemdata['id'] + '"';
        see_name = '<i class="eye icon"></i>';
    } else {
        see_onclick = 'onclick="mh_report(' + itemdata['id'] + ',\'card\')"';
        see_id = 'id="report_cc_' + itemdata['id'] + '"';
        see_name = '<i class="gavel icon"></i> Ticket';
        see_dis = 'disabled';
        if (itemdata['resqueid'] * 1 > 0) {
            see_dis = 'disabled';
        } else {
            see_dis = 'disabled';
        }
    }

    if (itemdata['ch_st'] === '0' && itemdata['fst'] === '0') {
        stt_onclick = 'onclick="send_to_check(' + itemdata['id'] + ')"';
        stt_id = '';
        stt_name = 'check';
        //see_dis='disabled';
    }
    if (itemdata['ch_st'] === '1' && itemdata['fst'] === '0') {
        stt_onclick = 'onclick="get_card_one(' + itemdata['id'] + ')"';
        stt_id = 'id="cc_status_' + itemdata['id'] + '"';
        stt_name = 'checking';
        see_dis = 'disabled';
    }
    if (itemdata['ch_st'] === '2' && itemdata['fst'] === '0') {
        stt_onclick = 'onclick="get_card_one(' + itemdata['id'] + ')"';
        stt_id = 'id="cc_status_' + itemdata['id'] + '"';
        stt_name = 'rechecking';
        see_dis = 'disabled';
    }
    if (itemdata['ch_st'] === '3' && itemdata['fst'] === '1') {
        stt_onclick = '';
        stt_id = '';
        stt_name = 'good';
        stt_dis = 'disabled';
        see_dis = 'disabled';
    }
    if (itemdata['ch_st'] === '3' && itemdata['fst'] === '2') {
        stt_onclick = '';
        stt_id = '';
        stt_name = 'bad';
        stt_dis = 'disabled';
        see_dis = 'disabled';
    }
    if (itemdata['ch_st'] === '3' && itemdata['fst'] === '3') {
        stt_onclick = '';
        stt_id = '';
        stt_name = 'refund';
        stt_dis = 'disabled';
        see_dis = 'disabled';
    }
    if (itemdata['ch_st'] === '3' && itemdata['fst'] === '4') {
        stt_onclick = '';
        stt_id = '';
        stt_name = 'bad';
        stt_dis = 'disabled';
        see_dis = 'disabled';
    }
    if (itemdata['ch_st'] === '0' && itemdata['fst'] === '5') {
        stt_onclick = '';
        stt_id = '';
        stt_name = 'times up';
        stt_dis = 'disabled';
        see_dis = '';
    }
    if (itemdata['ch_st'] === '3' && itemdata['fst'] === '6') {
        stt_onclick = '';
        stt_id = '';
        stt_name = 'fiftycode';
        stt_dis = 'disabled';
        see_dis = 'disabled';
    }
    if (itemdata['ch_st'] === '3' && itemdata['fst'] === '7') {
        stt_onclick = '';
        stt_id = '';
        stt_name = 'fiftycode';
        stt_dis = 'disabled';
        see_dis = 'disabled';
    }
    if (itemdata['ch_st'] === '3' && itemdata['fst'] === '8') {
        stt_onclick = '';
        stt_id = '';
        stt_name = 'error';
        stt_dis = 'disabled';
        see_dis = 'disabled';
    }
    if (itemdata['ch_st'] === '3' && itemdata['fst'] === '9') {
        stt_onclick = '';
        stt_id = '';
        stt_name = 'cc errror';
        stt_dis = 'disabled';
        see_dis = 'disabled';
    }
    if (itemdata['ch_st'] === '3' && itemdata['fst'] === '10') {
        stt_onclick = '';
        stt_id = '';
        stt_name = 'cc error';
        stt_dis = 'disabled';
        see_dis = 'disabled';
    }
    if (itemdata['fst'] === '11') {
        stt_onclick = '';
        stt_id = '';
        stt_name = 'refund';
        stt_dis = 'disabled';
        see_dis = 'disabled';
    }

    if (itemdata['ch_st'] === '0' && itemdata['refund'] === '2' && itemdata['fst'] !== '11') {
        stt_onclick = '';
        stt_id = '';
        stt_name = 'norefund';
        stt_dis = 'disabled';
        see_dis = '';
    }

    return '<div class="ui very compact tiny basic buttons">\n' +
        '        <div class="ui very small button disabled">myinfo</div>\n' +
        '        <div class="ui very small button" onclick="check3ds(' + itemdata['id'] + ')">3DS</div>\n' +
        '              <div class="ui button ' + see_dis + '" ' + see_id + ' ' + see_onclick + '>' + see_name + '</div>\n' +
        '              <div class="ui button ' + stt_dis + '" ' + stt_id + ' ' + stt_onclick + '>' + stt_name + '</div>\n' +
        '            </div>';

}

function send_to_check(id) {
    $.ajax({
        type: 'get',
        url: '/cc_list.php?to_check=' + id,
        success: function (result) {
            get_card_one(id);
            if (result === '1') {
                $('#lowbal').modal('show');
            }
        },
        error: function () {
            setTimeout(function () {
                send_to_check(id);
            }, 3000);
        }
    });
}

function update_daycc(daycc) {
    $.ajax({
        dataType: 'json',
        type: 'get',
        url: '/cc_list.php?get_daycc=' + daycc,
        beforeSend: function () {
            $('#upd_' + daycc).addClass('red');
        },
        success: function (result) {
            $('#ccday_' + daycc).html('');
            update_dayblock(daycc, result)
            balance();
        },
        complete: function () {
            $('#upd_' + daycc).removeClass('red');
        },
        error: function () {
            setTimeout(function () {
                get_basket(daycc);
            }, 5000);
        }
    });
}

function update_dayblock(cid, data) {
    $.each(data, function (inddata, itemdata) {
        card_line_set(cid, itemdata, 2);
    });

}

function send_to_check_dayscc(daycc) {
    $.ajax({
        type: 'get',
        url: '/cc_list.php?to_check_daycc=' + daycc,
        beforeSend: function () {
        },
        success: function (result) {
            update_daycc(daycc);
            if (result === '1') {
                $('#notenmon').modal('show');
            }
        },
        complete: function () {
        },
        error: function () {
            setTimeout(function () {
                send_to_check_dayscc(daycc);
            }, 5000);
        }
    });
}

//___________________________________


// ADDMONEY--------------------------
function payment_create(type) {
    $.ajax({
        dataType: "json",
        type: 'get',
        url: '/money_add.php?type=' + type,
        beforeSend: function () {
            $('#addbut_' + type).text('get data');
        },
        success: function (item) {
            let iin='';
            if (type === '5' || type === 5) {
                iin =
                    '<tr>\n' +
                    '        <td colspan="2"><h3 class="item" style="color: darkred"><strong>Minimum Deposit 50 USDT</strong></h3></td>\n' +
                    '      </tr>' +
                    '<tr>\n';
            }

            if (item.error === 'noadr') {
                alert('Wait 5 min and try again!');
            } else {
                if (item.details !== undefined) {
                    $('#pay_data').html('');
                    $('#pay_data').html(
                        iin +
                        '<tr>\n' +
                        '        <td class="right aligned">COIN:</td>\n' +
                        '        <td>' + item.type + '</td>\n' +
                        '      </tr>' +
                        '<tr>\n' +
                        '        <td class="right aligned">Wallet:</td>\n' +
                        '        <td><strong>' + item.details + '</strong></td>\n' +
                        '      </tr>'
                    );
                    $('#pay_info').modal('show');
                } else {
                    alert('The payment system is not working. try later');
                }
            }
        },
        complete: function () {
            $('#addbut_' + type).text('Add');
        },
        error: function () {
            alert('Refresh page and try again!');
        }
    });
}

//___________________________________

// VIEW MONEY HISTORY--------------------------

function get_history(type = 1) {
    let butts = '';
    $.ajax({
        dataType: "json",
        type: 'get',
        url: '/money_view.php?get_history=' + type,
        success: function (result) {
            $('#mhistory *').remove();
            $.each(result, function (ind, item) {
                if (item.status === 'opened') {
                    item.status = 'wait payment';
                }
                if (item.status === 'confirmed') {
                    item.status = 'received';
                }

                butts = '';
                if (item.status !== 'received') {
                    butts = '<div class="ui very compact tiny basic buttons">\n' +
                        '            <div class="ui tiny icon button" onclick="mh_report(' + item.id + ',\'order\')"><i class="gavel icon"></i></div>\n' +
                        '          <div class="ui tiny icon button" onclick="check_order(' + item.id + ')"><i class="search icon"></i></div>\n' +
                        '          </div>';
                }

                $('#mhistory').append('<tr>\n' +
                    '        <th class="center aligned">' + item.id + '</th>\n' +
                    '        <th class="center aligned">' + item.date + '</th>\n' +
                    '        <th class="center aligned">' + item.type + '</th>\n' +
                    '        <th class="center aligned">' + item.details + '</th>\n' +
                    '        <th class="center aligned">$' + item.balance + '</th>\n' +
                    '        <th class="center aligned">' + item.status + '</th>\n' +
                    '        <th class="center aligned">' + butts + '</th>\n' +
                    '      </tr>')
            });
        },
        error: function () {
            document.location = "/money_view.php";
        }
    });
}

function check_order(id) {
    $.ajax({
        type: 'get',
        url: '/money_view.php?check_order=' + id,
        success: function (result) {
            if (result === '1') {
                alert('payment received');
                get_history(1);
            }
            if (result === '0') {
                alert('wait payment');
            }
        }
    });
}

// --------------------------

// REPORTS  --------------------------
function mh_report(id, type) {
    var link;
    if (type === 'order') {
        link = '/money_view';
    }
    if (type === 'card') {
        link = '/cc_list';
    }
    $.ajax({
        type: 'get',
        url: link + '.php?rtid=' + id + '&service=' + type,
        success: function (result) {
            $('#ticid').text(id);
            $('#report_text').text(result);
            $('#add_report').modal('show');
        }
    });
}

// --------------------------

// CHANGE PASSWORD--------------------------
function chword_q() {
    $.ajax({
        dataType: 'json',
        type: 'post',
        url: '/ch_password.php',
        data: 'current_pass=' + $('#passwordq').val(),
        success: function (result) {
            if (result.status === 1) {
                $('#quicktext').html(
                    '<table class="ui very basic stacked compact table">\n' +
                    '        <tr>\n' +
                    '          <td class="right aligned two wide">New password:</td>\n' +
                    '          <td class="left aligned two wide"><strong>' + result.new + '</strong></td>\n' +
                    '        </tr>\n' +
                    '        <tr>\n' +
                    '          <td colspan="2" class="red"><strong>*save this password and re-login.</strong></td>\n' +
                    '        </tr>\n' +
                    '</table>');
            } else {
                $('#quicktext').text('Password not changed.');
            }
            $('#quickchpass').modal('show');
        }
    });
}

// --------------------------

//END OF FILE//









