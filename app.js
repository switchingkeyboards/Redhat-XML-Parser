const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const axios = require("axios");
const { parse, validate, getTraversalObj } = require("fast-xml-parser");
const util = require("util");
const url = "http://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml";
const _ = require("lodash");
const e = require("express");

/**
 * Express instance
 * @public
 */
const app = express();

// parse body params and attach them to req.body
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// enable CORS - Cross Origin Resource Sharing
app.use(cors());

app.use(bodyParser.json());

app.get("/", async function (req, res) {
  try {
    // Fetch XML from URL
    const response = await axios.get(url);
    const XML = response.data;
    // Check validity of XML file
    if (validate(XML) === true) {
      // Parse XML into a basic JSON using fast-xml-parser
      const tObj = getTraversalObj(XML, {
        ignoreAttributes: false,
        parseAttributeValue: true,
        attributeNamePrefix: "",
      });

      const tests = tObj.child.oval_definitions[0].child.tests[0].child;

      console.log(tests);

      //   TODO: Map out the tests, and use test ID to match for the corresponding comments
      const matchTest = (test) => {
        console.log(test);
        const match = _.find(tests, ["tagname", test]);
        return match;
      };

      const definitions =
        tObj.child.oval_definitions[0].child.definitions[0].child.definition;

      // Initialize empty array
      let advisoryArr = [];

      definitions.forEach(({ child }) => {
        const { metadata, criteria } = child;

        const meta = metadata[0].child;
        const advi = meta.advisory[0].child;
        const crit = criteria[0].child;
        const cves = advi.cve && advi.cve.map((c) => c.val);
        const cpe_list =
          advi.affected_cpe_list &&
          advi.affected_cpe_list[0].child.cpe.map((c) => c.val);

        const checkNesting = (obj) => {
          if (Object.keys(obj)[0] === "criterion") {
            return Object.values(obj)[0].map((c) => {
              return {
                // [c.parent.attrsMap.operator]: matchTest(c.attrsMap.test_ref),
                [c.parent.attrsMap.operator]: c.attrsMap.comment.split(" is "),
              };
            });
          } else if (Object.keys(obj)[0] === "criteria") {
            return Object.values(obj)[0].map((c) => {
              return {
                [c.attrsMap.operator]: checkNesting(c.child),
              };
            });
          }
        };

        const criteria_list = () => {
          const list =
            crit.criteria[0].child.criteria &&
            crit.criteria[0].child.criteria.map((c) => {
              return checkNesting(c.child);
            });
          return list && list[0];
        };

        const advisoryObj = {
          title: meta.title[0].val,
          fixes_cve: cves,
          severity: advi.severity[0].val,
          affected_cpe: cpe_list,
          criteria: criteria_list(),
        };

        advisoryArr.push(advisoryObj);
      });

      //   console.log("RESULT=========================");
      //   console.log(advisoryArr);

      res.json({ advisory: advisoryArr });
    }
  } catch (error) {
    console.log(error);
  }
});

app.get("/raw", async function (req, res) {
  try {
    const response = await axios.get(url);
    const XML = response.data;
    if (validate(XML) === true) {
      const JSON = parse(XML, {
        ignoreAttributes: false,
        parseAttributeValue: true,
        attributeNamePrefix: "",
      });
      res.json(JSON);
      console.log(JSON);
    }
  } catch (error) {
    console.log(error);
  }
});

app.get("/ping", async function (req, res) {
  res.send("pong");
});

app.listen(8080);
