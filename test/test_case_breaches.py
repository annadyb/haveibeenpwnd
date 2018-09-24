import pytest
import os
import logging
import json
import validators
import requests
from ratelimiter import RateLimiter
from datetime import datetime


headers = {'User-Agent': 'pytest-api-study-wsb', 'From': 'oliff@tlen.pl'}
rate_limiter = RateLimiter(max_calls=1, period=1.5)


@pytest.fixture(scope="session")
def apiv2_url():
    """returns api v2 url""" 
    return "https://haveibeenpwned.com/api/v2"


@pytest.fixture(scope="session")
def breaches_url(apiv2_url):
    """returns api v2 url/breaches"""
    return apiv2_url + "/breaches"


@pytest.fixture(scope="session")
def all_breaches(breaches_url):
    """returns list of all breaches"""
    with rate_limiter:
        return requests.get(breaches_url, headers=headers).json();

# TC01
def test_count_breaches(all_breaches):
    """count elements in breaches list"""
    assert len(all_breaches) >= 283

# TC02
@pytest.fixture(params=["adobe.com", "avast.com", "badoo.com", "aipai.com"])
def breaches_by_domain_request(request, breaches_url):
    """returns response for breaches by given existing domain"""
    par = {"domain": request.param, "includeUnverified": "true"}
    with rate_limiter:
        return requests.get(breaches_url, params=par, headers=headers)


def test_breaches_by_domain_status_code(breaches_by_domain_request):
    """checks status code of breaches by domain"""
    assert breaches_by_domain_request.status_code == 200


def test_breaches_by_domain_is_on_breaches_list(breaches_by_domain_request, all_breaches):
    """checks if breaches by domain is on_breaches list"""
    json_by_domain = breaches_by_domain_request.json()
    assert [breach for breach in json_by_domain if breach not in all_breaches] == []

# TC03
@pytest.fixture(params=["gmail.com", "wp.pl", "onet.pl", "przykladowastrona.pl"])
def not_existing_domain_request(request, breaches_url):
    """returns response for breaches by given not existing domain"""
    par = {"domain": request.param, "includeUnverified": "true"}
    with rate_limiter:        
        return requests.get(breaches_url, params=par, headers=headers)


def test_breaches_by_not_existing_domain_status_code(not_existing_domain_request):
    """checks status code of breaches by domain"""
    assert not_existing_domain_request.status_code == 200


def test_breaches_by_not_existing_domain(not_existing_domain_request):
    """checks breaches by not existing domain"""
    json_by_domain = not_existing_domain_request.json()
    assert json_by_domain  == []


# TC04
@pytest.fixture(scope="session")
def breach_url(apiv2_url):
    """returns api v2 url for given breach"""
    return apiv2_url + "/breach/{0}"


@pytest.fixture(params=["Adobe", "BeautifulPeople", "126", "7k7k"])
def breaches_by_name(request, breach_url):
    """returns breach by name"""
    url = breach_url.format(request.param)
    with rate_limiter:
        resp = requests.get(url, headers=headers)
    return resp.json()


def test_breaches_by_name(breaches_by_name, all_breaches):
    """check breaches by name - for name existing in the list of all breaches"""
    assert breaches_by_name in all_breaches


# TC05
@pytest.fixture(params=["ABC", "Ania", "AhaShar"])
def breaches_by_not_existing_name(request, breach_url):
    """returns response for not existing name"""
    url = breach_url.format(request.param)
    with rate_limiter:
        resp = requests.get(url, headers=headers)
    return resp


def test_not_existing_name(breaches_by_not_existing_name):
    """check status code - for name not existing in the list of all breaches"""
    assert breaches_by_not_existing_name.status_code == 404


# TC06
@pytest.fixture()
def column_names(scope="session"):
    """returns column names from file"""
    if not os.path.isfile("data/columns.txt"):
        logging.error("there is no data/columns.txt file")
        return {}
    with open("data/columns.txt") as f: 
        lines = f.readlines()
    names = {line.strip() for line in lines}
    logging.info("file data/columns.txt contains "+str(len(names))+" column names")
    return names


def test_column_names(all_breaches,column_names):
    """checks if every breach has given columns"""
    if len(column_names)==0:
        pytest.fail("there is no data/columns.txt file or file is empty")
    errors = []
    for breach in all_breaches:
        if not column_names.issubset( breach.keys() ):
            errors.append(breach)
            logging.error("at least one of the column from data/columns.txt is not in breach: "+str(breach))
    assert not errors


# TC07
def test_format_of_column_Name(all_breaches):
    """checks format of Name column"""
    errors = []
    for breach in all_breaches:
        if not isinstance(breach["Name"], str):
            errors.append(breach)
            logging.error("column Name in breach: "+str(breach)+" has wrong format")            
    assert not errors


def test_if_column_Name_is_not_empty(all_breaches):
    """checks if column Name is nor empty"""
    errors = []
    for breach in all_breaches:
        if breach["Name"] == "":
            errors.append(breach)
            logging.error("column Name in breach: "+str(breach)+" is empty")                        
    assert not errors


def test_format_of_column_PwnCount(all_breaches):
    """checks format of PwnCount column"""
    errors = []
    for breach in all_breaches:
        if not isinstance(breach["PwnCount"], int):
            errors.append(breach)
            logging.error("column PwnCount in breach: "+str(breach)+" has wrong format")                                    
    assert not errors


def test_format_of_column_Domain(all_breaches):
    """checks format of Domain column"""
    errors = []
    for breach in all_breaches:
        if breach["Domain"] != "" and not validators.domain(breach["Domain"]):
            errors.append(breach)
            logging.error("column Domain in breach: "+str(breach)+" has wrong format")                                                
    assert not errors


def test_format_of_column_BreachDate(all_breaches):
    """checks format of BreachDate columns"""
    errors = []
    for breach in all_breaches:
        if not datetime.strptime(breach["BreachDate"], "%Y-%m-%d"):
            errors.append(breach)
            logging.error("column BreachDate in breach: "+str(breach)+" has wrong format")                                                            
    assert not errors


# TC08
@pytest.fixture(scope="session")
def data_classes_json(apiv2_url):
    """returns list of all dataclasses"""
    url = apiv2_url + "/dataclasses"
    with rate_limiter:
        req = requests.get(url, headers=headers)
    return req.json()


def test_data_classes(all_breaches, data_classes_json): 
    """checks format of DataClasses columns"""
    errors = []
    for breach in all_breaches:
        if not set(breach["DataClasses"]).issubset(data_classes_json):
            errors.append(breach)
            logging.error("list DataClasses in breach: "+str(breach)+" contains wrong DataClasses")                                                                        
    assert not errors

            
# TC09
def pytest_generate_tests(metafunc):
    """dynamic generates parameter 'breach_file'"""
    files = [file for file in os.listdir("data/") if file.endswith(".json")]
    if "breach_file" in metafunc.fixturenames:
        metafunc.parametrize("breach_file", files)


@pytest.fixture()
def saved_breach(breach_file):
    """returns data of breach from file""" 
    with open("data/"+breach_file) as f: 
        data = json.load(f)
    logging.info("read data from "+str(breach_file))        
    return data


def test_saved_breach(all_breaches, saved_breach):
    """checks if breach (from file) exists on list of all breach"""
    assert saved_breach in all_breaches
