import requests

url = "https://safety.skku.edu/Safety/LabMng/Details?LabNo="

for i in range(1000, 10000):
    print(i)
    if requests.get(url + str(i)).status_code != 500:
        break