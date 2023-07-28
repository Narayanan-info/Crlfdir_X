const fs = require('fs').promises;
const path = require('path');
const axios = require('axios');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const { SingleBar, Presets } = require('cli-progress'); // Import cli-progress

// ASCII Banner
const banner = `

  ██████╗██████╗ ██╗     ███████╗██████╗ ██╗██████╗         ██╗  ██╗
 ██╔════╝██╔══██╗██║     ██╔════╝██╔══██╗██║██╔══██╗        ╚██╗██╔╝
 ██║     ██████╔╝██║     █████╗  ██║  ██║██║██████╔╝         ╚███╔╝ 
 ██║     ██╔══██╗██║     ██╔══╝  ██║  ██║██║██╔══██╗         ██╔██╗ 
 ╚██████╗██║  ██║███████╗██║     ██████╔╝██║██║  ██║███████╗██╔╝ ██╗
  ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═════╝ ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  
                                                     
CRLF Bug Scanner
`;

// Function to scan for CRLF bugs
async function scanCrlfBugs(urls, wordlist, outputFile) {
  const payloads = await loadPayloads(wordlist);
  const results = [];

  console.log('Start CRLF bug scanning');
  console.log('URLs:', urls);

  const progressBar = new SingleBar({
    format: 'Scanning |' + '{bar}' + '| {percentage}% || {value}/{total} URLs \n',
    barCompleteChar: '\u2588',
    barIncompleteChar: '\u2591',
    hideCursor: true,
  }, Presets.shades_classic);

  progressBar.start(urls.length, 0);

  await Promise.all(urls.map(url => checkUrlForCrlfVulnerability(url, payloads, results, progressBar)));

  progressBar.stop();

  if (results.length === 0) {
    console.log('Not vulnerable to CRLF.');
  }

  await writeResultsToFile(results, outputFile);
}

// Function to load payloads from the wordlist file
async function loadPayloads(wordlistFile) {
  const wordlistPath = path.resolve(wordlistFile);
  try {
    await fs.access(wordlistPath, fs.constants.R_OK);
  } catch (error) {
    console.error('Wordlist file not found:', wordlistFile);
    process.exit(1);
  }

  const payloads = (await fs.readFile(wordlistPath, 'utf8')).split('\n');
  return payloads.filter((payload) => payload.trim() !== '');
}

// Function to check for CRLF vulnerability in a URL with multiple payloads
async function checkUrlForCrlfVulnerability(url, payloads, results, progressBar) {
  const requests = payloads.map(async (payload) => {
    const fullUrl = url + payload;
    try {
      const response = await axios.get(fullUrl, { validateStatus: null });
      var statusCode = "403, 400, 500";
      // console.log(!statusCode.includes(response.status));
      if (!statusCode.includes(response.status) && hasCrlfVulnerability(response.data)) {
        results.push({ url, payload, response: response.data });
        displayVulnerableUrls(url, [payload]);
      }
    } catch (error) {
      // Handle errors
    }
  });

  // if ((response.status === 301 || response.status === 302) && hasCrlfVulnerability(response.data)) {

  await Promise.all(requests);
  progressBar.increment();
}

// Function to check if the response data has CRLF vulnerability
function hasCrlfVulnerability(data) {
  return /(?:\r?\n|%0D%0A|%0a|%0d)/i.test(data);
}

// Function to display vulnerable URLs and their payloads
function displayVulnerableUrls(url, vulnerablePayloads) {
  if (vulnerablePayloads.length > 0) {
    for (const payload of vulnerablePayloads) {
      console.log(`Possible To CRLF [ 🚨 ] - URL ${url}${payload}`);
    }
  }
}

// Function to write CRLF vulnerability results to a file
async function writeResultsToFile(results, outputFile) {
  const outputData = results
    .map((result) => `${result.url}${result.payload}\n`)
    .join('\n');
  await fs.writeFile(outputFile, outputData);
  console.log('CRLF bug scan completed. Results saved to', outputFile);
}

// Main thread execution
(async () => {
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
    .usage(banner) // Display banner with options on -h/--help
    .argv;

  // If user runs with -h or --help, yargs will display the banner along with options and exit
  if (argv.h || argv.help) {
    process.exit(0);
  }

  // Display the ASCII banner if not showing help
  console.log(banner);

  if (argv.url) {
    // Scan a single URL
    console.log('Scanning a single URL:', argv.url);
    await scanCrlfBugs([argv.url], argv.wordlist, argv.output);
  } else if (argv.file) {
    // Read URLs from a file and scan each of them
    console.log('Scanning URLs from a file:', argv.file);
    const urlList = (await fs.readFile(argv.file, 'utf8')).split('\n').filter(url => url.trim() !== '');
    await scanCrlfBugs(urlList, argv.wordlist, argv.output);
  } else {
    console.error('Please provide either a single URL (-u) or a file containing URLs (-f).');
    process.exit(1);
  }
})();