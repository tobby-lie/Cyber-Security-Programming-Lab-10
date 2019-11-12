import geoip2.database
from time import time
from sklearn import metrics

reader = geoip2.database.Reader('GeoLite2-City.mmdb')


def countryiso(ip):
    try:
        loc = reader.city(ip)
    except:
        return None
    return loc.country.iso_code

def iplong(ip):
    try:
        loc = reader.city(ip)
    except:
        return None
    return loc.location.longitude

def iplat(ip):
    try:
        loc = reader.city(ip)
    except:
        return None
    return loc.location.latitude


def bench_k_means(estimator, name, labels, data, sample_size):
    t0 = time()
    estimator.fit(data)
    print('%-9s\t%.2fs\t%i\t%.3f' %
          (name, (time() - t0), estimator.inertia_, metrics.silhouette_score
          (data, estimator.labels_, metric='euclidean', sample_size=sample_size)))



             # metrics.homogeneity_score(labels, estimator.labels_),
             # metrics.completeness_score(labels, estimator.labels_),
             # metrics.v_measure_score(labels, estimator.labels_),
             # metrics.adjusted_rand_score(labels, estimator.labels_),
             # metrics.adjusted_mutual_info_score(labels,  estimator.labels_),
             # metrics.silhouette_score(data, estimator.labels_,
             #                          metric='euclidean',
             #                          sample_size=sample_size)))
