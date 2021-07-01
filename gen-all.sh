#!/bin/sh

if [ ! -d venv ]; then
	echo "Venv not found, creating..."
	python3 -m venv venv
	. venv/bin/activate
	pip install -r requirements.txt
fi

. venv/bin/activate

if [ ! -d sigma ]; then
	echo "Sigma repo not found, cloning..." 
	git clone https://github.com/Neo23x0/sigma.git
fi

echo "Updating sigma rules..."
cd sigma
git pull --no-rebase
cd ..

mkdir -p dashboards/windows

for d in $(ls sigma/rules/); do
	[ "$d" = "windows" ] && continue
	python create_dashboard.py -di "sigma/rules/$d" --config splunk-windows-all.yml
	mv dashboard_code.txt "dashboards/$d-dashboard.xml"
done

for d in $(ls sigma/rules/windows/); do
	python create_dashboard.py -di "sigma/rules/windows/$d" --config splunk-windows-all.yml
	mv dashboard_code.txt "dashboards/windows/$d-dashboard.xml"
done

echo "Generated $(find dashboards -name "*.xml" | wc -l) .xml files under ./dashboards/"
