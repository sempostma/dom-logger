import * as React from 'react';
import useOnlineStatus, { getPoller } from '../src/index'
import { render, fireEvent, waitFor } from '@testing-library/react'
import fetchMock from 'fetch-mock';
import { renderHook } from "@testing-library/react-hooks";
import { act } from "react-test-renderer";
import { before } from 'lodash';

const App = () => {
    const onlineStatus = useOnlineStatus()

    return (
        <p>Is online: {onlineStatus ? 'Yes' : 'No'}</p>
    )
}

const fetch = global.fetch

describe('run common tests', () => {
    beforeEach(() => {
        global.fetch = fetch
        jest.restoreAllMocks();
        fetchMock.restore();
        if (getPoller.cache.clear) getPoller.cache.clear()
    })

    it('returns the appropriate network status', async () => {
        jest.spyOn(navigator, 'onLine', 'get').mockReturnValue(true);
        const onlineApp = render(<App />)
        expect(onlineApp.container.textContent).toEqual('Is online: Yes');
        jest.spyOn(navigator, 'onLine', 'get').mockReturnValue(false);
        await act(async () => {
            fireEvent(window, new Event('offline'))
        })
        expect(onlineApp.container.textContent).toEqual('Is online: No')
    });

    it('returns the appropriate network status', async () => {
        const url = 'https://google.com/generate_204'
        jest.spyOn(navigator, 'onLine', 'get').mockReturnValue(true);
        fetchMock.mock(url, 200);
        const { result } = renderHook(() => useOnlineStatus(url));
        expect(result.current).toEqual(true);
        fetchMock.restore()
        fetchMock.mock(url, 500);
        await act(async () => {
            jest.runOnlyPendingTimers()
            jest.runOnlyPendingTimers()
            jest.clearAllTimers()
        })
        expect(result.current).toEqual(false)
        expect(fetchMock.called()).toEqual(true)
    });

    it('only calls the polling url once even though multiple hooks are running', async () => {
        const url = 'https://google.com/generate_204'
        const amount = 5
        jest.spyOn(navigator, 'onLine', 'get').mockReturnValue(true);
        fetchMock.mock(url, 200);
        for (let i = 0; i < amount; i++) {
            renderHook(() => useOnlineStatus(url))
        }
        await act(async () => {
            jest.runOnlyPendingTimers()
            jest.runOnlyPendingTimers()
            jest.clearAllTimers()
        })
        expect(fetchMock.calls().length).toEqual(1)
    });

    it('only calls the polling url once for each unique polling specification', async () => {
        const url = 'https://google.com/generate_204'
        const amount = 5
        jest.spyOn(navigator, 'onLine', 'get').mockReturnValue(true);
        fetchMock.mock(url, 200);
        for (let i = 0; i < amount; i++) {
            renderHook(() => useOnlineStatus(url))
        }
        for (let i = 0; i < amount; i++) {
            renderHook(() => useOnlineStatus(url, { timeout: 5000 }))
        }
        await act(async () => {
            jest.runOnlyPendingTimers()
            jest.runOnlyPendingTimers()
            jest.clearAllTimers()
        })
        expect(fetchMock.calls().length).toEqual(2)
    });
});