const fs = require('fs');
const path = require('path');
const axios = require('axios');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const { SingleBar, Presets } = require('cli-progress'); // Import cli-progress

// Function to scan for CRLF bugs
async function scanCrlfBugs(urls, wordlist, outputFile) {
  const payloads = loadPayloads(wordlist);
  const results = [];

  console.log('Start CRLF bug scanning');
  console.log('URLs:', urls);

  // Create a progress bar
  const progressBar = new SingleBar({
    format: 'Scanning |' + '{bar}' + '| {percentage}% || {value}/{total} URLs',
    barCompleteChar: '\u2588',
    barIncompleteChar: '\u2591',
    hideCursor: true,
  }, Presets.shades_classic);

  progressBar.start(urls.length, 0);

  for (const url of urls) {
    const vulnerablePayloads = [];
    for (const payload of payloads) {
      const fullUrl = url + payload;
      const result = await checkCrlfVulnerability(fullUrl, payload);
      if (result !== null) {
        results.push(result);
        vulnerablePayloads.push(payload);
      }
    }
    displayVulnerableUrls(url, vulnerablePayloads);
    progressBar.increment();
  }

  progressBar.stop();

  if (results.length === 0) {
    console.log('Not vulnerable to CRLF.');
  }

  writeResultsToFile(results, outputFile);
}

// Function to load payloads from the wordlist file
function loadPayloads(wordlistFile) {
  const wordlistPath = path.resolve(wordlistFile);
  if (!fs.existsSync(wordlistPath)) {
    console.error('Wordlist file not found:', wordlistFile);
    process.exit(1);
  }

  const payloads = fs.readFileSync(wordlistPath, 'utf8').split('\n');
  return payloads.filter((payload) => payload.trim() !== '');
}

// Function to check for CRLF vulnerability in a URL with a given payload
function checkCrlfVulnerability(url, payload) {
  return axios
    .get(url)
    .then((response) => {
      const hasCrlf = /(?:\r?\n|%0D%0A|%0a|%0d)/i.test(response.data);
      return hasCrlf ? { url, payload, response: response.data } : null;
    })
    .catch((error) => {
        console.log(error.message)
      return null;
    });
}

// Function to display vulnerable URLs and their payloads
function displayVulnerableUrls(url, vulnerablePayloads) {
  if (vulnerablePayloads.length > 0) {
    console.log(`\nVulnerable URL: ${url}`);
    for (const payload of vulnerablePayloads) {
      console.log(`Payload: ${payload}`);
      console.log('Response:');
      console.log('Vulnerable to CRLF.');
    }
  }
}

// Function to write CRLF vulnerability results to a file
function writeResultsToFile(results, outputFile) {
  const outputData = results
    .map((result) => `URL: ${result.url}\nPayload: ${result.payload}\nResponse:\n${result.response}\n`)
    .join('\n');
  fs.writeFileSync(outputFile, outputData);
  console.log('CRLF bug scan completed. Results saved to', outputFile);
}

// Main thread execution
const argv = yargs(hideBin(process.argv))
  .option('u', {
    alias: 'url',
    describe: 'Single URL to scan for CRLF bugs',
    type: 'string',
  })
  .option('f', {
    alias: 'file',
    describe: 'File containing URLs to scan (one URL per line)',
    type: 'string',
  })
  .option('w', {
    alias: 'wordlist',
    describe: 'Wordlist file for fuzzing paths',
    type: 'string',
    demandOption: true,
  })
  .option('o', {
    alias: 'output',
    describe: 'Output file to save CRLF bug results',
    type: 'string',
    default: 'crlf-bug-results.txt',
  })
  .help('h')
  .alias('h', 'help')
  .argv;

if (argv.url) {
  // Scan a single URL
  console.log('Scanning a single URL:', argv.url);
  scanCrlfBugs([argv.url], argv.wordlist, argv.output);
} else if (argv.file) {
  // Read URLs from a file and scan each of them
  console.log('Scanning URLs from a file:', argv.file);
  const urlList = fs.readFileSync(argv.file, 'utf8').split('\n').filter(url => url.trim() !== '');
  scanCrlfBugs(urlList, argv.wordlist, argv.output);
} else {
  console.error('Please provide either a single URL (-u) or a file containing URLs (-f).');
  process.exit(1);
}
