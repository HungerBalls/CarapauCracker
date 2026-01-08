# CVE API Configuration

## NVD API Setup

CarapauCracker uses the NIST National Vulnerability Database (NVD) API to check for known vulnerabilities.

### Getting an API Key (Free)

1. Visit https://nvd.nist.gov/developers/request-an-api-key
2. Fill in the form with your details
3. You'll receive the API key via email within minutes

### Configuration

#### Option 1: Local Development (.env file)

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and add your API key:
   ```bash
   NVD_API_KEY=your-api-key-here
   ```

3. The `.env` file is automatically ignored by git

#### Option 2: GitHub Secrets (for CI/CD)

1. Go to your repository Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Name: `NVD_API_KEY`
4. Value: your API key
5. Click "Add secret"

#### Option 3: Environment Variable

```bash
export NVD_API_KEY="your-api-key-here"
python main.py
```

### Rate Limits

- **Without API key**: 5 requests per 30 seconds
- **With API key**: 50 requests per 30 seconds

The tool automatically adjusts request timing based on whether an API key is present.

### Troubleshooting

If you see "rate limit exceeded":
- Wait 30 seconds
- Make sure your API key is correctly configured
- Check that `.env` file is in the project root directory
