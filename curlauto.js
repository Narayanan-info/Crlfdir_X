const https = require("https");
const fs = require("fs");

// Get the filename from the command-line arguments
const args = process.argv.slice(2);
const inputFile = args.includes("-f") ? args[args.indexOf("-f") + 1] : null;

if (!inputFile) {
  console.log("Please provide an input file using '-f' option.");
  process.exit(1);
}

// Read the list of URLs from the input file
const urls = fs.readFileSync(inputFile, "utf8").split(/\r?\n/).filter(Boolean);

// Function to make a request and save the output to the output file
function makeRequest(url, outputFile) {
  const req = https.get(url, (res) => {
    const writeStream = fs.createWriteStream(outputFile, { flags: "a" }); // Use 'a' flag for appending
    writeStream.write(`Vulnerable URL: ${url}\n`);
    writeStream.write("Response Headers:\n");
    writeStream.write("HTTP/" + res.httpVersion + " " + res.statusCode + " " + res.statusMessage + "\n");
    for (const [name, value] of Object.entries(res.headers)) {
      writeStream.write(name + ": " + value + "\n");
    }
    writeStream.write("==================================================================================\n");
    writeStream.end();
    console.log("Response for " + url + " saved to " + outputFile);
  });

  req.on("error", (error) => {
    console.error("Error occurred for " + url + ":", error.message);
  });
}

// Output file to save all responses
const outputFile = "output.txt";

// Loop through each URL and make requests
urls.forEach((url) => {
  makeRequest(url, outputFile);
});