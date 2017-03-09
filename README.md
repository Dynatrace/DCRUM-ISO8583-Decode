# ISO 8583 script for DC RUM

The script enables you to monitor the applications using the ISO 8583 protocol to exchange electronic transactions made by cardholders using the payment cards. Two versions of the protocol are supported, ISO 8583:1993 and ISO 8583:2003 - choose one of the two scripts depending on your protocol version. The scripts report the operation names and messages issued in the communication.

Note that the ISO 8583:1993 script provides versatile means of analysis and can be used as a starting template for new implementations. On the other hand, ISO 8583:2003  is just an example, based on limited scenarios which may not be sufficient to use is as a base for further development.

## What is Dynatrace DC RUM?

[Data Center Real User Monitoring (DC RUM)](http://www.dynatrace.com/en/data-center-rum/) is an effective, non-intrusive choice for monitoring business applications that are accessed by employees, partners, and customers outside the corporate enterprise or from the corporate network (intranet or extranet).

## Which DC RUM versions are compatible with the ISO 8583 script?

 * ISO 8583:1993 - AMD HS
 * ISO 8583:2003 - 12.3 or later, Classic AMD.

## Prerequisites

The script for the ISO 8583:1993 protocol requires a 16-bit big-endian message length prefix. Requests are matched with responses using unique values of the "System trace audit number (STAN)" field.

## Where can I find the newest version of the ISO 8583 script?

We host the latest version of the ISO 8583 script in this GitHub repository.

## How can I run the script from sources?

See [Using and Maintaining Software Services Definitions Based on Universal Decode](https://community.dynatrace.com/community/display/DCRUM124/Using+and+Maintaining+Software+Services+Definitions+Based+on+Universal+Decode).

## Problems? Questions? Suggestions?

This offering is [Dynatrace Community Supported](https://community.dynatrace.com/community/display/DL/Support+Levels#SupportLevels-Communitysupported/NotSupportedbyDynatrace(providedbyacommunitymember)).
Feel free to share any problems, questions, and suggestions with your peers on the Dynatrace Community
[Data Center RUM forum](https://answers.dynatrace.com/spaces/160/index.html).
You can also contact the [Dynatrace eXpert Services](https://www.dynatrace.com/services/on-demand/?_ga=1.101974532.448700715.1471865886) to obtain a fully supported application performance monitoring solution delivery using this decode.

## License

Licensed under the BSD License. See the [LICENSE](LICENSE) file for details.
