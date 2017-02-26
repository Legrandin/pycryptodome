#!/bin/sh

BASE="https://ci.appveyor.com/api"

# Get state of last job
LAST_JOB=$(curl -s ${BASE}/projects/legrandin/pycryptodome | jq '.build')

BRANCH=$(echo ${LAST_JOB} | jq -r '.branch')
STATUS=$(echo ${LAST_JOB} | jq -r '.status')

echo "Last build done for branch '${BRANCH}' with status '${STATUS}'"
if [ ${STATUS} != "success" ]; then
	exit 1
fi

# Dowload one file per job
JOBS=$(echo ${LAST_JOB} | jq -r '.jobs[].jobId')
for job_id in ${JOBS}; do
	FILE=$(curl -s ${BASE}/buildjobs/${job_id}/artifacts | jq -r .[0].fileName)
	wget ${BASE}/buildjobs/${job_id}/artifacts/${FILE}
done
