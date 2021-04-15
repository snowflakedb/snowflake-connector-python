#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from datetime import datetime, timedelta

import pytz
from dateutil.parser import parse

from snowflake.connector.converter import ZERO_EPOCH, _generate_tzinfo_from_tzoffset


def test_fetch_various_timestamps(conn_cnx):
    """More coverage of timestamp.

    Notes:
        Currently TIMESTAMP_LTZ is not tested.
    """
    PST_TZ = "America/Los_Angeles"
    epoch_times = ["1325568896", "-2208943503", "0", "-1"]
    timezones = ["+07:00", "+00:00", "-01:00", "-09:00"]
    fractions = "123456789"
    data_types = ["TIMESTAMP_TZ", "TIMESTAMP_NTZ"]

    data = []
    for dt in data_types:
        for et in epoch_times:
            if dt == "TIMESTAMP_TZ":
                for tz in timezones:
                    tzdiff = (int(tz[1:3]) * 60 + int(tz[4:6])) * (
                        -1 if tz[0] == "-" else 1
                    )
                    tzinfo = _generate_tzinfo_from_tzoffset(tzdiff)
                    try:
                        ts = datetime.fromtimestamp(float(et), tz=tzinfo)
                    except (OSError, ValueError):
                        ts = ZERO_EPOCH + timedelta(seconds=float(et))
                        if pytz.utc != tzinfo:
                            ts += tzinfo.utcoffset(ts)
                        ts = ts.replace(tzinfo=tzinfo)
                    data.append(
                        {
                            "scale": 0,
                            "dt": dt,
                            "inp": ts.strftime("%Y-%m-%d %H:%M:%S{tz}".format(tz=tz)),
                            "out": ts,
                        }
                    )
                    for idx in range(len(fractions)):
                        scale = idx + 1
                        if idx + 1 != 6:  # SNOW-28597
                            try:
                                ts0 = datetime.fromtimestamp(float(et), tz=tzinfo)
                            except (OSError, ValueError):
                                ts0 = ZERO_EPOCH + timedelta(seconds=float(et))
                                if pytz.utc != tzinfo:
                                    ts0 += tzinfo.utcoffset(ts0)
                                ts0 = ts0.replace(tzinfo=tzinfo)
                            ts0_str = ts0.strftime(
                                "%Y-%m-%d %H:%M:%S.{ff}{tz}".format(
                                    ff=fractions[: idx + 1], tz=tz
                                )
                            )
                            ts1 = parse(ts0_str)
                            data.append(
                                {"scale": scale, "dt": dt, "inp": ts0_str, "out": ts1}
                            )
            elif dt == "TIMESTAMP_LTZ":
                # WIP. this test work in edge case
                tzinfo = pytz.timezone(PST_TZ)
                ts0 = datetime.fromtimestamp(float(et))
                ts0 = pytz.utc.localize(ts0).astimezone(tzinfo)
                ts0_str = ts0.strftime("%Y-%m-%d %H:%M:%S")
                ts1 = ts0
                data.append({"scale": 0, "dt": dt, "inp": ts0_str, "out": ts1})
                for idx in range(len(fractions)):
                    ts0 = datetime.fromtimestamp(float(et))
                    ts0 = pytz.utc.localize(ts0).astimezone(tzinfo)
                    ts0_str = ts0.strftime(
                        "%Y-%m-%d %H:%M:%S.{ff}".format(ff=fractions[: idx + 1])
                    )
                    ts1 = ts0 + timedelta(
                        seconds=float("0.{}".format(fractions[: idx + 1]))
                    )
                    data.append(
                        {"scale": idx + 1, "dt": dt, "inp": ts0_str, "out": ts1}
                    )
            else:
                # TIMESTAMP_NTZ
                try:
                    ts0 = datetime.fromtimestamp(float(et))
                except (OSError, ValueError):
                    ts0 = ZERO_EPOCH + timedelta(seconds=(float(et)))
                ts0_str = ts0.strftime("%Y-%m-%d %H:%M:%S")
                ts1 = parse(ts0_str)
                data.append({"scale": 0, "dt": dt, "inp": ts0_str, "out": ts1})
                for idx in range(len(fractions)):
                    try:
                        ts0 = datetime.fromtimestamp(float(et))
                    except (OSError, ValueError):
                        ts0 = ZERO_EPOCH + timedelta(seconds=(float(et)))
                    ts0_str = ts0.strftime(
                        "%Y-%m-%d %H:%M:%S.{ff}".format(ff=fractions[: idx + 1])
                    )
                    ts1 = parse(ts0_str)
                    data.append(
                        {"scale": idx + 1, "dt": dt, "inp": ts0_str, "out": ts1}
                    )
    sql = "SELECT "
    for d in data:
        sql += "'{inp}'::{dt}({scale}), ".format(
            inp=d["inp"], dt=d["dt"], scale=d["scale"]
        )
    sql += "1"
    with conn_cnx() as cnx:
        cur = cnx.cursor()
        cur.execute(
            """
ALTER SESSION SET TIMEZONE='{tz}';
""".format(
                tz=PST_TZ
            )
        )
        rec = cur.execute(sql).fetchone()
        for idx, d in enumerate(data):
            comp, lower, higher = _in_range(d["out"], rec[idx])
            assert (
                comp
            ), "data: {d}: target={target}, lower={lower}, higher={" "higher}".format(
                d=d, target=rec[idx], lower=lower, higher=higher
            )


def _in_range(reference, target):
    lower = reference - timedelta(microseconds=1)
    higher = reference + timedelta(microseconds=1)
    return lower <= target <= higher, lower, higher
