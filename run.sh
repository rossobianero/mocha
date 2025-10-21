source .env

docker build -t ai-sec-agent:cli .

docker run --rm \
  -e OPENAI_API_KEY \
  -e GITHUB_TOKEN \
  -e AI_PR_OPEN \
  -e GIT_AUTHOR_NAME \
  -e GIT_AUTHOR_EMAIL \
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
