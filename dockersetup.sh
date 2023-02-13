CONTAINER_ALREADY_STARTED="CONTAINER_ALREADY_STARTED_PLACEHOLDER"
if [ ! -e $CONTAINER_ALREADY_STARTED ]; then
        touch $CONTAINER_ALREADY_STARTED
        echo "-- First container startup --"
        echo " {"\
         "  \"gateway_conf\": {" \
         "      \"gateway_ID\": \"${gateway_ID}\"," \
         "      \"server_address\": \"${server_address}\"," \
         "      \"serv_port_up\": ${serv_port_up}," \
         "      \"serv_port_down\": ${serv_port_down}" \
         "    }"\
         "  }" > /home/middleman/configs/config.json

        echo "middleman_ENVs=\"${middleman_ENVs}\"" > /home/middleman/middleman.conf
        cat /home/middleman/configs/config.json && cat /home/middleman/middleman.conf
else
        echo "-- Not first container startup --"
fi
python3 /home/middleman/gateways2miners.py -p ${middleman_port} -c /home/middleman/configs/ -d
