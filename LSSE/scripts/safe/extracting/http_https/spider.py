# Light-Scan Framework - Network Security Scanning Framework
# Copyright (C) 2026 Adam Boulaaz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

"""
Light-Scan Scripting Engine (LSSE)
Script Name : spider
Author : Adam Boulaaz, ognamgeek
Arguments
--> Required Arguments
----> --url
--> Optional Arguments
----> --mxd
----> --mxp
Categorie :safe/discovery/http_https
"""

import threading
import time
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


class Spider:
    def __init__(self, max_workers=5):
        self.max_workers = max_workers
        self.visited = set()
        self.results = []
        self.lock = threading.Lock()
        self.print_lock = threading.Lock()

    def crawl_page(
        self, url: str, depth: int
    ) -> tuple[dict | None, list[str]]:
        try:

            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.title.get_text(strip=True) if soup.title else "No title"

                links = []
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                        full_url = urljoin(url, href)
                        links.append(full_url)

                result = {
                    'url': url,
                    'depth': depth,
                    'title': title,
                    'status': response.status_code,
                    'links_found': len(links),
                    'links': links
                }

                with self.lock:
                    self.visited.add(url)
                    self.results.append(result)

                return result, links
            else:
                with self.lock:
                    self.visited.add(url)

                return None, []

        except Exception as e:
            with self.print_lock:
                print(f"Error crawling {url}: {e}")
            with self.lock:
                self.visited.add(url)
            return None, []

    def spider(
        self, start_url: str, max_pages: int = 50, max_depth: int = 2
    ) -> list[dict]:
        print("-" * 60)
        print(f"Starting demo parallel spider at: {start_url}")
        print(f"Max pages: {max_pages}, Max depth: {max_depth}")
        print("-" * 60)

        queue = deque([(start_url, 0)])
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}

            while (len(self.results) < max_pages and
                   (queue or futures) and
                   not (len(self.results) >= max_pages and not queue)):

                while queue and len(futures) < self.max_workers and len(self.results) < max_pages:
                    url, depth = queue.popleft()

                    if url in self.visited or depth > max_depth:
                        continue

                    future = executor.submit(self.crawl_page, url, depth)
                    futures[future] = (url, depth)

                if futures:
                    wait(
                        list(futures.keys()),
                        timeout=1,
                        return_when=FIRST_COMPLETED,
                    )
                    for future in list(futures.keys()):
                        if future.done():
                            url, depth = futures[future]

                            try:
                                result, new_links = future.result()

                                if result and depth < max_depth:
                                    for link in new_links:
                                        if (link not in self.visited and
                                                link not in [u for u, _ in queue] and
                                                not any(link == u for u, _ in futures.values())):
                                            queue.append((link, depth + 1))

                            except Exception as e:
                                with self.print_lock:
                                    print(f"Task error for {url}: {e}")

                            del futures[future]

        elapsed_time = time.time() - start_time

        print(f"Crawling completed in {elapsed_time:.2f} seconds!")
        print(f"Total pages crawled: {len(self.results)}")
        print(f"Pages per second: {len(self.results) / elapsed_time:.2f}")
        print("-" * 60)

        self.print_results()
        return self.results

    def print_results(self) -> None:

        depth_groups = {}
        for result in self.results:
            depth = result['depth']
            if depth not in depth_groups:
                depth_groups[depth] = []
            depth_groups[depth].append(result)

        for depth in sorted(depth_groups.keys()):
            pages = depth_groups[depth]
            print(f"\nDepth {depth} ({len(pages)} pages):")
            for i, page in enumerate(pages, 1):
                print(f"  {i:2}. {page['title']} ")
                print(f"      {page['url']}")
                print(f"      Links found: {page['links_found']}")
