# NVD API Configuration

## Quick Setup

### 1. Get Your Free API Key

1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Fill out the form with your email
3. Receive API key via email (usually within minutes)

### 2. Configure Locally

Create a `.env` file in the project root:

```bash
cp .env.example .env
```

Edit `.env` and add your key:

```
NVD_API_KEY=12e4ef89-1215-46d3-851a-b722450c20f7
```

### 3. Configure for GitHub Actions (Optional)

If using CI/CD:

1. Go to repository Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Name: `NVD_API_KEY`
4. Value: Your API key
5. Click "Add secret"

## Rate Limits

- **Without API key**: 5 requests per 30 seconds
- **With API key**: 50 requests per 30 seconds

The tool automatically handles rate limiting.

## Troubleshooting

**Error: "NVD API rate limit exceeded"**
- Wait 30 seconds between scan batches
- Ensure your API key is correctly configured

**Error: "No NVD_API_KEY found"**
- Check that `.env` file exists in project root
- Verify the key name is exactly `NVD_API_KEY`

## API Documentation

Official NVD API docs: https://nvd.nist.gov/developers/vulnerabilities
