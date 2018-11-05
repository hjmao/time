// JavaScript Document
var timerID ;

function tzone(os, ds, cl)
{
    this.ct = new Date(0) ;		// datetime
    this.os = os ;		// GMT offset
    this.ds = ds ;		// has daylight savings
    this.cl = cl ;		// font color
}

function UpdateClocks()
{
var ct = new Array(
new tzone(-10, 0, 'silver'),
new tzone(-9, 1, 'silver'),
new tzone(-8, 1, 'silver'),
new tzone(-8, 1, 'silver'),
new tzone(-8, 1, 'silver'),
new tzone(-8, 1, 'silver'),
new tzone(-7, 1, 'silver'),
new tzone(-7, 1, 'silver'),
new tzone(-7, 0, 'silver'),
new tzone(-7, 1, 'silver'),
new tzone(-6, 1, 'silver'),
new tzone(-6, 1, 'silver'),
new tzone(-6, 1, 'silver'),
new tzone(-6, 1, 'silver'),
new tzone(-6, 1, 'silver'),
new tzone(-6, 1, 'silver'),
new tzone(-6, 1, 'silver'),
new tzone(-6, 1, 'silver'),
new tzone(-6, 0, 'silver'),
new tzone(-6, 0, 'silver'),
new tzone(-6, 0, 'silver'),
new tzone(-6, 1, 'silver'),
new tzone(-5, 1, 'silver'),
new tzone(-5, 0, 'silver'),
new tzone(-5, 1, 'silver'),
new tzone(-5, 1, 'silver'),
new tzone(-5, 1, 'silver'),
new tzone(-5, 1, 'silver'),
new tzone(-5, 1, 'silver'),
new tzone(-5, 1, 'silver'),
new tzone(-5, 1, 'silver'),
new tzone(-5, 0, 'silver'),
new tzone(-5, 0, 'silver'),
new tzone(-5, 0, 'silver'),
new tzone(-5, 1, 'silver'),
new tzone(-5, 1, 'silver'),
new tzone(-5, 1, 'silver'),
new tzone(-5, 0, 'silver'),
new tzone(-5, 0, 'silver'),
new tzone(-5, 0, 'silver'),
new tzone(-5, 0, 'silver'),
new tzone(-5, 1, 'silver'),
new tzone(-4, 1, 'silver'),
new tzone(-4, 1, 'silver'),
new tzone(-3.5, 1, 'silver'),
new tzone(-3, 0, 'silver'),
new tzone(-3, 1, 'silver'),
new tzone(-3, 1, 'silver'),
new tzone(-3, 1, 'silver'),
new tzone(-3, 1, 'silver'),
new tzone(0, 0, 'silver'),
new tzone(0, 1, 'silver'),
new tzone(0, 0, 'silver'),
new tzone(0, 1, 'silver'),
new tzone(0, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 0, 'silver'),
new tzone(+1, 0, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+1, 1, 'silver'),
new tzone(+2, 0, 'silver'),
new tzone(+2, 1, 'silver'),
new tzone(+2, 1, 'silver'),
new tzone(+2, 1, 'silver'),
new tzone(+2, 1, 'silver'),
new tzone(+2, 1, 'silver'),
new tzone(+2, 1, 'silver'),
new tzone(+2, 0, 'silver'),
new tzone(+2, 1, 'silver'),
new tzone(+2, 1, 'silver'),
new tzone(+2, 1, 'silver'),
new tzone(+2, 0, 'silver'),
new tzone(+2, 1, 'silver'),
new tzone(+2, 1, 'silver'),
new tzone(+2, 1, 'silver'),
new tzone(+2, 1, 'silver'),
new tzone(+2, 1, 'silver'),
new tzone(+3, 0, 'silver'),
new tzone(+3, 0, 'silver'),
new tzone(+3, 1, 'silver'),
new tzone(+3, 0, 'silver'),
new tzone(+3, 1, 'silver'),
new tzone(+3, 0, 'silver'),
new tzone(+3, 0, 'silver'),
new tzone(+3, 0, 'silver'),
new tzone(+3, 0, 'silver'),
new tzone(+3.5, 1, 'silver'),
new tzone(+4, 0, 'silver'),
new tzone(+4.5, 0, 'silver'),
new tzone(+5, 0, 'silver'),
new tzone(+5, 0, 'silver'),
new tzone(+5, 0, 'silver'),
new tzone(+5, 0, 'silver'),
new tzone(+5.5, 0, 'silver'),
new tzone(+5.5, 0, 'silver'),
new tzone(+5.5, 0, 'silver'),
new tzone(+5.75, 0, 'silver'),
new tzone(+6, 0, 'silver'),
new tzone(+6.5, 0, 'silver'),
new tzone(+7, 0, 'silver'),
new tzone(+7, 0, 'silver'),
new tzone(+7, 0, 'silver'),
new tzone(+7, 0, 'silver'),
new tzone(+8, 0, 'silver'),
new tzone(+8, 0, 'silver'),
new tzone(+8, 0, 'silver'),
new tzone(+8, 0, 'silver'),
new tzone(+8, 0, 'silver'),
new tzone(+8, 0, 'silver'),
new tzone(+8, 0, 'silver'),
new tzone(+8, 0, 'silver'),
new tzone(+9, 0, 'silver'),
new tzone(+9, 0, 'silver'),
new tzone(+9.5, 0, 'silver'),
new tzone(+10, 1, 'silver'),
new tzone(+10, 0, 'silver'),
new tzone(11, 1, 'silver'),
new tzone(11, 1, 'silver'),
new tzone(11, 1, 'silver'),
new tzone(+9.5, 1, 'silver'),
new tzone(+12, 1, 'silver'),
new tzone(+12, 1, 'silver'),
new tzone(+12, 0, 'silver'),
new tzone(13, 1, 'silver'),
new tzone(13.75, 1, 'silver'),
new tzone(+14, 0, 'silver')
    ) ;

    var dt = new Date() ;	// [GMT] time according to machine clock
    var startDST = new Date(dt.getFullYear(), 3, 1) ;

    while (startDST.getDay() != 0)
        startDST.setDate(startDST.getDate() + 1) ;

    var endDST = new Date(dt.getFullYear(), 9, 31) ;

    while (endDST.getDay() != 0)
        endDST.setDate(endDST.getDate() - 1) ;

    var ds_active ;		// DS currently active
    if (startDST < dt && dt < endDST)
        ds_active = 1 ;
    else
        ds_active = 0 ;

// Adjust each clock offset if that clock has DS and in DS.

//    for(n=0 ; n<ct.length ; n++)
//        if (ct[n].ds == 1 && ds_active == 1) ct[n].os++ ;

// compensate time zones

    var printstr = "";

    gmdt = new Date() ;
    for (n=0 ; n<ct.length ; n++) {
        ct[n].ct = new Date(gmdt.getTime() + ct[n].os * 3600 * 1000) ;
    }

document.all.Clockk0.innerHTML = ClockString(ct[0].ct);
document.all.Clockk1.innerHTML = ClockString(ct[1].ct);
document.all.Clockk2.innerHTML = ClockString(ct[2].ct);
document.all.Clockk3.innerHTML = ClockString(ct[3].ct);
document.all.Clockk4.innerHTML = ClockString(ct[4].ct);
document.all.Clockk5.innerHTML = ClockString(ct[5].ct);
document.all.Clockk6.innerHTML = ClockString(ct[6].ct);
document.all.Clockk7.innerHTML = ClockString(ct[7].ct);
document.all.Clockk8.innerHTML = ClockString(ct[8].ct);
document.all.Clockk9.innerHTML = ClockString(ct[9].ct);
document.all.Clockk10.innerHTML = ClockString(ct[10].ct);
document.all.Clockk11.innerHTML = ClockString(ct[11].ct);
document.all.Clockk12.innerHTML = ClockString(ct[12].ct);
document.all.Clockk13.innerHTML = ClockString(ct[13].ct);
document.all.Clockk14.innerHTML = ClockString(ct[14].ct);
document.all.Clockk15.innerHTML = ClockString(ct[15].ct);
document.all.Clockk16.innerHTML = ClockString(ct[16].ct);
document.all.Clockk17.innerHTML = ClockString(ct[17].ct);
document.all.Clockk18.innerHTML = ClockString(ct[18].ct);
document.all.Clockk19.innerHTML = ClockString(ct[19].ct);
document.all.Clockk20.innerHTML = ClockString(ct[20].ct);
document.all.Clockk21.innerHTML = ClockString(ct[21].ct);
document.all.Clockk22.innerHTML = ClockString(ct[22].ct);
document.all.Clockk23.innerHTML = ClockString(ct[23].ct);
document.all.Clockk24.innerHTML = ClockString(ct[24].ct);
document.all.Clockk25.innerHTML = ClockString(ct[25].ct);
document.all.Clockk26.innerHTML = ClockString(ct[26].ct);
document.all.Clockk27.innerHTML = ClockString(ct[27].ct);
document.all.Clockk28.innerHTML = ClockString(ct[28].ct);
document.all.Clockk29.innerHTML = ClockString(ct[29].ct);
document.all.Clockk30.innerHTML = ClockString(ct[30].ct);
document.all.Clockk31.innerHTML = ClockString(ct[31].ct);
document.all.Clockk32.innerHTML = ClockString(ct[32].ct);
document.all.Clockk33.innerHTML = ClockString(ct[33].ct);
document.all.Clockk34.innerHTML = ClockString(ct[34].ct);
document.all.Clockk35.innerHTML = ClockString(ct[35].ct);
document.all.Clockk36.innerHTML = ClockString(ct[36].ct);
document.all.Clockk37.innerHTML = ClockString(ct[37].ct);
document.all.Clockk38.innerHTML = ClockString(ct[38].ct);
document.all.Clockk39.innerHTML = ClockString(ct[39].ct);
document.all.Clockk40.innerHTML = ClockString(ct[40].ct);
document.all.Clockk41.innerHTML = ClockString(ct[41].ct);
document.all.Clockk42.innerHTML = ClockString(ct[42].ct);
document.all.Clockk43.innerHTML = ClockString(ct[43].ct);
document.all.Clockk44.innerHTML = ClockString(ct[44].ct);
document.all.Clockk45.innerHTML = ClockString(ct[45].ct);
document.all.Clockk46.innerHTML = ClockString(ct[46].ct);
document.all.Clockk47.innerHTML = ClockString(ct[47].ct);
document.all.Clockk48.innerHTML = ClockString(ct[48].ct);
document.all.Clockk49.innerHTML = ClockString(ct[49].ct);
document.all.Clockk50.innerHTML = ClockString(ct[50].ct);
document.all.Clockk51.innerHTML = ClockString(ct[51].ct);
document.all.Clockk52.innerHTML = ClockString(ct[52].ct);
document.all.Clockk53.innerHTML = ClockString(ct[53].ct);
document.all.Clockk54.innerHTML = ClockString(ct[54].ct);
document.all.Clockk55.innerHTML = ClockString(ct[55].ct);
document.all.Clockk56.innerHTML = ClockString(ct[56].ct);
document.all.Clockk57.innerHTML = ClockString(ct[57].ct);
document.all.Clockk58.innerHTML = ClockString(ct[58].ct);
document.all.Clockk59.innerHTML = ClockString(ct[59].ct);
document.all.Clockk60.innerHTML = ClockString(ct[60].ct);
document.all.Clockk61.innerHTML = ClockString(ct[61].ct);
document.all.Clockk62.innerHTML = ClockString(ct[62].ct);
document.all.Clockk63.innerHTML = ClockString(ct[63].ct);
document.all.Clockk64.innerHTML = ClockString(ct[64].ct);
document.all.Clockk65.innerHTML = ClockString(ct[65].ct);
document.all.Clockk66.innerHTML = ClockString(ct[66].ct);
document.all.Clockk67.innerHTML = ClockString(ct[67].ct);
document.all.Clockk68.innerHTML = ClockString(ct[68].ct);
document.all.Clockk69.innerHTML = ClockString(ct[69].ct);
document.all.Clockk70.innerHTML = ClockString(ct[70].ct);
document.all.Clockk71.innerHTML = ClockString(ct[71].ct);
document.all.Clockk72.innerHTML = ClockString(ct[72].ct);
document.all.Clockk73.innerHTML = ClockString(ct[73].ct);
document.all.Clockk74.innerHTML = ClockString(ct[74].ct);
document.all.Clockk75.innerHTML = ClockString(ct[75].ct);
document.all.Clockk76.innerHTML = ClockString(ct[76].ct);
document.all.Clockk77.innerHTML = ClockString(ct[77].ct);
document.all.Clockk78.innerHTML = ClockString(ct[78].ct);
document.all.Clockk79.innerHTML = ClockString(ct[79].ct);
document.all.Clockk80.innerHTML = ClockString(ct[80].ct);
document.all.Clockk81.innerHTML = ClockString(ct[81].ct);
document.all.Clockk82.innerHTML = ClockString(ct[82].ct);
document.all.Clockk83.innerHTML = ClockString(ct[83].ct);
document.all.Clockk84.innerHTML = ClockString(ct[84].ct);
document.all.Clockk85.innerHTML = ClockString(ct[85].ct);
document.all.Clockk86.innerHTML = ClockString(ct[86].ct);
document.all.Clockk87.innerHTML = ClockString(ct[87].ct);
document.all.Clockk88.innerHTML = ClockString(ct[88].ct);
document.all.Clockk89.innerHTML = ClockString(ct[89].ct);
document.all.Clockk90.innerHTML = ClockString(ct[90].ct);
document.all.Clockk91.innerHTML = ClockString(ct[91].ct);
document.all.Clockk92.innerHTML = ClockString(ct[92].ct);
document.all.Clockk93.innerHTML = ClockString(ct[93].ct);
document.all.Clockk94.innerHTML = ClockString(ct[94].ct);
document.all.Clockk95.innerHTML = ClockString(ct[95].ct);
document.all.Clockk96.innerHTML = ClockString(ct[96].ct);
document.all.Clockk97.innerHTML = ClockString(ct[97].ct);
document.all.Clockk98.innerHTML = ClockString(ct[98].ct);
document.all.Clockk99.innerHTML = ClockString(ct[99].ct);
document.all.Clockk100.innerHTML = ClockString(ct[100].ct);
document.all.Clockk101.innerHTML = ClockString(ct[101].ct);
document.all.Clockk102.innerHTML = ClockString(ct[102].ct);
document.all.Clockk103.innerHTML = ClockString(ct[103].ct);
document.all.Clockk104.innerHTML = ClockString(ct[104].ct);
document.all.Clockk105.innerHTML = ClockString(ct[105].ct);
document.all.Clockk106.innerHTML = ClockString(ct[106].ct);
document.all.Clockk107.innerHTML = ClockString(ct[107].ct);
document.all.Clockk108.innerHTML = ClockString(ct[108].ct);
document.all.Clockk109.innerHTML = ClockString(ct[109].ct);
document.all.Clockk110.innerHTML = ClockString(ct[110].ct);
document.all.Clockk111.innerHTML = ClockString(ct[111].ct);
document.all.Clockk112.innerHTML = ClockString(ct[112].ct);
document.all.Clockk113.innerHTML = ClockString(ct[113].ct);
document.all.Clockk114.innerHTML = ClockString(ct[114].ct);
document.all.Clockk115.innerHTML = ClockString(ct[115].ct);
document.all.Clockk116.innerHTML = ClockString(ct[116].ct);
document.all.Clockk117.innerHTML = ClockString(ct[117].ct);
document.all.Clockk118.innerHTML = ClockString(ct[118].ct);
document.all.Clockk119.innerHTML = ClockString(ct[119].ct);
document.all.Clockk120.innerHTML = ClockString(ct[120].ct);
document.all.Clockk121.innerHTML = ClockString(ct[121].ct);
document.all.Clockk122.innerHTML = ClockString(ct[122].ct);
document.all.Clockk123.innerHTML = ClockString(ct[123].ct);
document.all.Clockk124.innerHTML = ClockString(ct[124].ct);
document.all.Clockk125.innerHTML = ClockString(ct[125].ct);
document.all.Clockk126.innerHTML = ClockString(ct[126].ct);
document.all.Clockk127.innerHTML = ClockString(ct[127].ct);
document.all.Clockk128.innerHTML = ClockString(ct[128].ct);
document.all.Clockk129.innerHTML = ClockString(ct[129].ct);
document.all.Clockk130.innerHTML = ClockString(ct[130].ct);
document.all.Clockk131.innerHTML = ClockString(ct[131].ct);
document.all.Clockk132.innerHTML = ClockString(ct[132].ct);
document.all.Clockk133.innerHTML = ClockString(ct[133].ct);
document.all.Clockk134.innerHTML = ClockString(ct[134].ct);
document.all.Clockk135.innerHTML = ClockString(ct[135].ct);
document.all.Clockk136.innerHTML = ClockString(ct[136].ct);
document.all.Clockk137.innerHTML = ClockString(ct[137].ct);
document.all.Clockk138.innerHTML = ClockString(ct[138].ct);
document.all.Clockk139.innerHTML = ClockString(ct[139].ct);
document.all.Clockk140.innerHTML = ClockString(ct[140].ct);
document.all.Clockk141.innerHTML = ClockString(ct[141].ct);
    timerID = window.setTimeout("UpdateClocks()", 1001) ;
}


function ClockString(dt)
{
    var stemp ;
    var dt_year = dt.getUTCFullYear() ;
    var dt_month = dt.getUTCMonth() + 1 ;
    var dt_day = dt.getUTCDate() ;
    var dt_hour = dt.getUTCHours() ;
    var dt_minute = dt.getUTCMinutes() ;
    var dt_second = dt.getUTCSeconds() ;
    dt_year = dt_year.toString() ;

    if (dt_minute < 10)
        dt_minute = '0' + dt_minute ;

    if (dt_second < 10)
        dt_second = '0' + dt_second ;

    stemp = dt_year + '年' + dt_month + '月' + dt_day + '日';
    stemp = stemp + ' ' + dt_hour + ":" + dt_minute + ":" + dt_second;
    return stemp ;
}
