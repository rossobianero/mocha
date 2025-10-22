source .env

docker build -t ai-sec-agent:cli .

docker run --rm \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -e AI_FIX_MODEL="gpt-4o-mini" \
  -e GITHUB_TOKEN="$GITHUB_TOKEN" \
  -e AI_PR_OPEN=1 \
  -e GIT_AUTHOR_NAME="ai-fixer[bot]" \
  -e GIT_AUTHOR_EMAIL="ai-fixer[bot]@users.noreply.github.com" \
  -e FIXER_VERBOSE=1 \
  -v "$(pwd)/data":/data \
  -v "$(pwd)/repos":/repos \
  -v "$(pwd)":/app \
  ai-sec-agent:cli \
  python /app/runner.py \
    --config /app/config.yaml \
    --repo-filter Vulnerable.Net \
    --fix \
    --apply \
    --patch-attempts 3
