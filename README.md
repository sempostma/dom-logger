# web-events-logger

Logs DOM events

## Usage

```javascript
import Logger from 'web-events-logger'

const logger = new Logger({ url: '/my-logging-endpoint' })

logger.captureError(new Error('Huh?'))

// automatically logs console errors, exceptions and csp violations
```

## License

License: MIT
