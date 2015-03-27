#!/bin/bash

# Author: Brandon Williams
# Description: This utility makes calls to the Red Hat CVE database to retrieve the CVE details.
# Usage: This script takes a list of CVEs as input and produces a report containing details, statements, and links to any related errata.
#        The input file should be plain text with one CVE per line. e.g.:
#
#        CVE-2015-0409
#        CVE-2015-0411
#        CVE-2015-0432
#        ...
#
# Syntax: redhat_cve_report.sh <CVE_List>

while read CVE
do
    # Here we go
    echo -e "Pulling details for $CVE"

    # Fortunately, the URL for CVEs in the database is based on the CVE number itself. \o/ for making things easy!
    CVE_URL="https://access.redhat.com/security/cve/$CVE"

#    echo -e $CVE_URL

    # This the HTML we get back for the requested CVE
    CVE_HTML=`curl -s $CVE_URL`

#    echo -e $CVE_HTML

    # If the CVE doesn't exist in the Red Hat CVE Database
    if [[ $CVE_HTML =~ .*not_found.* ]]
    then
        echo -e "NOT FOUND!"
        echo -e "---------------------------------------------------------------------------------------------------"

    # If the CVE does exist in the Red Hat CVE Database
    else

        set -f

        # Grab the classification (e.g. low, moderate, critical, etc.)
        if [[ $CVE_HTML =~ .*"http://www.redhat.com/security/updates/classification/".* ]]
        then
            IMPACT=`echo "$CVE_HTML" | grep '<td><a href="http://www.redhat.com/security/updates/classification/' | cut -f 3 -d '>' | cut -f 1 -d '<'`
        # Or not, if it doesn't exist in the HTML
        else
            IMPACT="N/A"
        fi

        # Grab the date the CVE was made public
        if [[ $CVE_HTML =~ .*"<th>Public:</th>".* ]]
        then
            PUBLIC=`echo "$CVE_HTML" | grep -A1 "<th>Public:</th>" | tail -n +2 | cut -f 2 -d '>' | cut -f 1 -d '<'`
        # Or not, if the date field has no data
        else
            PUBLIC="N/A"
        fi

        # Get any statements for the CVE and remove any HTML formatting
        if [[ $CVE_HTML =~ .*"<h2>Statement</h2>".* ]]
        then
            STATEMENT=`echo $CVE_HTML | sed -e 's/^.*<h2>Statement<\/h2>//'`

            if [[ $STATEMENT =~ .*"<h2>CVSS v2 metrics</h2>".* ]]
            then
                STATEMENT=`echo $STATEMENT | sed -e 's/<h2>CVSS v2 metrics<\/h2>.*//g' | sed -e 's/<br \/>/\n\n/g' | sed -e 's/.*<p>//g' | sed -e 's/<\/p>.*//g' | sed -e 's/<a href=".*">//g' | sed -e 's/<\/a>//g'`
            else
                STATEMENT=`echo $STATEMENT | sed -e 's/<h2>Red Hat security errata<\/h2>.*//g' | sed -e 's/<br \/>/\n\n/g' | sed -e 's/.*<p>//g' | sed -e 's/<\/p>.*//g' | sed -e 's/<a href=".*">//g' | sed -e 's/<\/a>//g'`
            fi
        # Not all CVEs have statements
        else
            STATEMENT="N/A"
        fi

        # Grab the details for the CVE and remove any HTML formatting
        if [[ $CVE_HTML =~ .*"<h2>Details</h2>".* ]]
        then
            DETAILS=`echo $CVE_HTML | sed -e 's/^.*<h2>Details<\/h2>//'`
            DETAILS=`echo $DETAILS | sed -e 's/<h2>Statement<\/h2>.*//g' | sed -e 's/<br \/>/\n\n/g' | sed -e 's/.*<blockquote class="indent"> //g' | sed -e 's/ <\/blockquote>.*//g'`
        # If there are no details
        else
            DETAILS="N/A"
        fi

        # Check out this magic. I'm not even sure how it works, but it does.
        # Find the Red Hat Security Errata table in the HTML, discard all HTML before it.
        ERRATA_LIST=`echo $CVE_HTML | sed -e 's/^.*Red Hat security errata//'`
        # Read to the next table containing External References. Toss that and everything that follows, then replace each </tr> in the HTML with a "|" so we can turn it into an array.
        ERRATA_LIST=`echo "${ERRATA_LIST%%External References*}" | sed -e 's/<\/tr>/\|/g'`

        # Make an array containing a list of errata released for this CVE
        OIFS="$IFS"
        IFS=$'|'
        ERRATA_ARRAY=($ERRATA_LIST)
        IFS="$OIFS"

        # Remove first array element... it's leftover HTML garbage
        unset ERRATA_ARRAY[0]

        # Remove last array element... it's also leftover HTML garbage
        unset ERRATA_ARRAY[${#ERRATA_ARRAY[@]}]

        # Finally, we print something readable
        echo -e "CVE URL: $CVE_URL"
        echo -e "Impact: $IMPACT"
        echo -e "Public: $PUBLIC"
        echo -e "Statement: $STATEMENT"
        echo -e "Details: $DETAILS"
        echo -e "Errata List: "

        set +f

        # If there are no errata available
        if [ ${#ERRATA_ARRAY[@]} -eq 0 ]
        then
            echo -e "N/A"
        # If there is a list of errata, let's make it pretty.
        else
            for ERRATA in "${ERRATA_ARRAY[@]}"
            do
                echo -e $ERRATA | sed -e 's/^<tr> <td>//g' | sed -e 's/<\/td> <td><a href="/ | /g' | sed -e 's/" class="internal">.*<\/a><\/td> <td>/ | /g' | sed -e 's/<\/td>//g'
            done
        fi

        echo -e "---------------------------------------------------------------------------------------------------"
        # Done with this one. Next!
    fi

done < $1