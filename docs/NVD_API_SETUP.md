# NVD API Setup Guide

## Getting Your Free API Key

1. Visit https://nvd.nist.gov/developers/request-an-api-key
2. Fill out the form with:
   - Your name
   - Email address
   - Organization (can be "Personal" or "Individual")
3. You'll receive the API key by email within minutes

## Local Setup (.env file)

1. Copy the example file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and add your API key:
   ```
   NVD_API_KEY=12e4ef89-1215-46d3-851a-b722450c20f7
   ```

3. **Never commit `.env` to GitHub!** (already in .gitignore)

## GitHub Secrets Setup (for CI/CD)

1. Go to your repository on GitHub
2. Settings → Secrets and variables → Actions
3. Click "New repository secret"
4. Name: `NVD_API_KEY`
5. Value: `your-api-key-here`
6. Click "Add secret"

## Rate Limits

- **Without API key**: 5 requests per 30 seconds
- **With API key**: 50 requests per 30 seconds (10x faster!)

## Benefits

✅ Official NIST database
✅ Always up-to-date
✅ Detailed CVSS scores
✅ Comprehensive vulnerability data
✅ Reliable and stable
