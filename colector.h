/*
 * colector.h
 *
 *  Created on: Feb 25, 2011
 *      Author: nuno
 */

#ifndef COLECTOR_H_
#define COLECTOR_H_

struct colected_info {
	int how_many_ports;
	long how_many_packets_processed;
	long how_many_inserts;
	long how_many_removes;

};


int collectInfo(struct colected_info *info);

#endif /* COLECTOR_H_ */
