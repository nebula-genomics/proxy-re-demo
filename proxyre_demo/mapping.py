import umbral


def int_to_point(num):
    """
    Encode a number, x, as a point by calculating g * x.

    Returns g * x.
    """
    if not isinstance(num, (int, umbral.curvebn.CurveBN)):
        raise TypeError("Please provide an int or umbral CurveBN")

    g = umbral.point.Point.get_generator_from_curve()

    # we want 0 to map to the elliptic curve's additive identity (infinity)
    # CurveBN.from_int() will fail if you pass 0, so do this check before calling it
    if num == 0:
        infinity = g - g
        return infinity

    if isinstance(num, int):
        num = umbral.curvebn.CurveBN.from_int(num)

    return g * num


def discrete_log(point):
    """
    Given a point, g * x, find x.

    Returns x.
    """
    g = umbral.point.Point.get_generator_from_curve()
    infinity = point - point

    curr_point = point
    discrete_log = 0
    while curr_point != infinity:
        curr_point -= g
        discrete_log += 1

    return discrete_log
