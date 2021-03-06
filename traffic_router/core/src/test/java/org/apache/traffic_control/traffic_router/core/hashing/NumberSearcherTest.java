/*
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.traffic_control.traffic_router.core.hashing;

import org.apache.traffic_control.traffic_router.core.hash.NumberSearcher;
import org.junit.Test;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

public class NumberSearcherTest {
	@Test
	public void itFindsClosest() {
		Double[] numbers = { 1.2, 2.3, 3.4, 4.5, 5.6 };

		NumberSearcher numberSearcher = new NumberSearcher();
		assertThat(numberSearcher.findClosest(numbers,3.4), equalTo(2));
		assertThat(numberSearcher.findClosest(numbers,1.9), equalTo(1));
		assertThat(numberSearcher.findClosest(numbers,1.3), equalTo(0));
		assertThat(numberSearcher.findClosest(numbers,6.7), equalTo(4));
		assertThat(numberSearcher.findClosest(numbers,0.1), equalTo(0));
	}
}
