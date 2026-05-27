import geoip2.database

# 读取 GeoLite 数据库
reader = geoip2.database.Reader(
    'GeoLite2-Country.mmdb'
)

def get_country(ip):

    try:

        response = reader.country(ip)

        return response.country.name

    except:

        return "Unknown"