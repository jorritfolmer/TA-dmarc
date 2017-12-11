import socket
from lxml import etree


# store XML string
xml_string = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?><feedback><report_metadata><org_name>acme.com</org_name><email>noreply-dmarc-support@acme.com</email><extra_contact_info>http://acme.com/dmarc/support</extra_contact_info><report_id>9391651994964116463</report_id><date_range><begin>1335571200</begin><end>1335657599</end></date_range></report_metadata><policy_published><domain>example.com</domain><adkim>r</adkim><aspf>r</aspf><p>none</p><sp>none</sp><pct>100</pct></policy_published><record><row><source_ip>72.150.241.94</source_ip><count>2</count><policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers><auth_results><dkim><domain>example.com</domain><result>fail</result><human_result></human_result></dkim><dkim><domain>example.org</domain><result>pass</result><human_result></human_result></dkim><spf><domain>example.com</domain><result>pass</result></spf></auth_results></record></feedback>"
# created XML elements from string
xml = etree.fromstring(xml_string)

# insert a source_ip/resolution element
records = xml.findall("record")
for record in records:
    # need to add source_ip resolution
    data_ip = record.findtext('row/source_ip')
    source_ip_tag = record.find("row/source_ip")
    print type(source_ip_tag)

    if 1 == 1:
        try:
            # self.helper.log_debug("rua2json: resolving %s" % data_ip)
            print "try line 1"
            # where should we add to report tree
            resolve = socket.gethostbyaddr(data_ip)
            print resolve[0]
            print "try line 2"
            ip_resolution = etree.SubElement(source_ip_tag, "ip_resolution")
            ip_resolution.text = resolve[0]
        except Exception:
            print "Exception 1"

print etree.tostring(source_ip_tag, pretty_print=True)
print etree.tostring(ip_resolution, pretty_print=True)
print etree.tostring(xml, pretty_print=True)
